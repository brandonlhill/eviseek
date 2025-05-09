import assemblyline_client
import asyncio
import json
import logging
import os
import threading
import time
import queue
from datetime import datetime
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from sshtunnel import SSHTunnelForwarder
from fastmcp import Client
import paramiko
from config import load_config
from logger import setup_logging

# Setup logging and config
log = setup_logging(level=logging.INFO)
config = load_config()

# SSH/SFTP configuration
SSH_HOST = config["ssh"]["host"]
SSH_PORT = config["ssh"]["port"]
SSH_USERNAME = config["ssh"]["username"]
SSH_PASSWORD = config["ssh"]["password"]
REMOTE_HOST = config["ssh"]["remote_host"]
REMOTE_PORT = config["ssh"]["remote_port"]

# Local configuration
ALERT_DB_PATH = os.path.expanduser(config["local"].get("alert_db_path", "~/.eviseek/alert_db.json"))
CHECK_INTERVAL = 10
BATCH_SIZE = config["local"].get("batch_size", 100)

# Shared queue for Strelka alerts
strelka_alert_queue = queue.Queue()

class MCPClientWrapper:
    def __init__(self):
        self.tunnel = None
        self.client = None

    def start_tunnel(self):
        self.tunnel = SSHTunnelForwarder(
            (SSH_HOST, SSH_PORT),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(REMOTE_HOST, REMOTE_PORT),
            local_bind_address=("127.0.0.1", 5001)
        )
        self.tunnel.start()
        log.info(f"SSH tunnel started at 127.0.0.1:{self.tunnel.local_bind_port}")

    async def start_client(self):
        url = f"http://127.0.0.1:{self.tunnel.local_bind_port}/sse"
        self.client = Client(url)
        await self.client.__aenter__()

    async def stop_client(self):
        if self.client:
            await self.client.__aexit__(None, None, None)
        if self.tunnel:
            self.tunnel.stop()
            log.info("SSH tunnel stopped.")

    async def call_tool(self, tool_name, args):
        return await self.client.call_tool(tool_name, args)

class AlertTracker:
    def __init__(self, db_path=ALERT_DB_PATH):
        self.db = TinyDB(db_path, storage=CachingMiddleware(JSONStorage))
        self.meta_table = self.db.table('_meta')
        self.alerts_table = self.db.table('alerts')
        self.lock = threading.Lock()

    def get_last_position(self):
        with self.lock:
            meta = self.meta_table.get(Query().type == 'meta')
            last = meta.get('last_from', 0) if meta else 0
            log.debug(f"[Tracker] Last known position: {last}")
            return last

    def update_last_position(self, from_):
        with self.lock:
            self.meta_table.upsert({'type': 'meta', 'last_from': from_}, Query().type == 'meta')
            self.db.storage.flush()

    def alert_exists(self, alert_id):
        with self.lock:
            return self.alerts_table.contains(Query().alert_id == alert_id)

    def save_alert(self, alert):
        with self.lock:
            log.info(f"[Tracker] Saving alert {alert['alert_id']} to DB")
            self.alerts_table.insert(alert)
            self.db.storage.flush()

    def get_all_alerts(self):
        with self.lock:
            return self.alerts_table.all()

class AssemblylineConnector:
    def __init__(self, host, user, password, queue, verify=False):
        self.host = host
        self.user = user
        self.password = password
        self.queue_name = queue
        self.client = None
        self.log = logging.getLogger("__main__")
        self._connect(verify=verify)

    def _connect(self, verify=False):
        try:
            self.client = assemblyline_client.get_client(self.host, auth=(self.user, self.password), verify=verify)
            self.log.info("Connected to Assemblyline at %s", self.host)
        except Exception as e:
            self.log.error("Connection failed: %s", e)
            raise

    def submit_full_analysis(self, filepath, description="Comprehensive Analysis", classification="TLP:C", metadata=None):
        if not os.path.isfile(filepath):
            self.log.error("File not found: %s", filepath)
            return None

        filename = os.path.basename(filepath)
        metadata = metadata or {}
        metadata.update({
            "source": "eviseek",
            "submitted_by": self.user,
            "campaign": "eviseek1"
        })

        params = {
            "classification": classification,
            "description": description,
            "name": filename,
            "deep_scan": True,
            "ignore_cache": True,
            "ignore_filtering": True,
            "ignore_recursion_prevention": True,
            "ignore_size": True,
            "max_extracted": 500,
            "max_supplementary": 500,
            "priority": 1000,
            "ttl": 30,
            "services": {
                "selected": [],
                # "excluded": [],
                # "resubmit": []
            },
            "service_spec": {
                #"Extract": {
                #    "password": "infected"
                #}
            }
        }

        try:
            result = self.client.ingest(
                path=filepath,
                nq=self.queue_name,
                params=params,
                metadata=metadata
            )
            ingest_id = result.get("ingest_id")
            self.log.info("Submitted %s, Ingest ID: %s", filename, ingest_id)
            return ingest_id
        except Exception as e:
            self.log.error("Submission failed: %s", e)
            return None

    def wait_for_result(self, ingest_id, poll_interval=3):
        self.log.info("Waiting for result for ingest ID: %s", ingest_id)
        while True:
            try:
                message = self.client.ingest.get_message(self.queue_name)
                if message and message.get("ingest_id") == ingest_id:
                    self.log.info("Received result for ingest ID: %s", ingest_id)
                    return message
            except Exception as e:
                self.log.warning("Polling error: %s", e)
            time.sleep(poll_interval)

    def get_full_submission(self, sid):
        try:
            result = self.client.submission(sid)
            self.log.info("Fetched submission SID: %s", sid)
            return result
        except Exception as e:
            self.log.error("Failed to fetch submission %s: %s", sid, e)
            return None

    def submit_and_collect(self, filepath):
        ingest_id = self.submit_full_analysis(filepath)
        if not ingest_id:
            return None

        message = self.wait_for_result(ingest_id)
        if not message:
            return None

        sid = message.get("submission", {}).get("sid")
        if sid:
            return self.get_full_submission(sid)
        else:
            self.log.warning("No SID in message.")
            return message

class AlertIngestorThread(threading.Thread):
    def __init__(self, shared_tracker, stop_event):
        super().__init__()
        self.stop_event = stop_event
        self.tracker = shared_tracker
        # TODO: need to add self.log! 

    def run(self):
        asyncio.run(self.ingest_loop())

    async def ingest_loop(self):
        mcp = MCPClientWrapper()
        mcp.start_tunnel()

        try:
            await mcp.start_client()
            from_position = self.tracker.get_last_position()

            while not self.stop_event.is_set():
                try:
                    result = await mcp.call_tool(
                        "elasticsearch_search",
                        {
                            "index": ".ds-logs-strelka-so-*",
                            "query": {"match_all": {}},
                            "size": BATCH_SIZE,
                            "from_": from_position  # <- fix this
                        }
                    )
                    try:
                        parsed = json.loads(result[0].text)
                        hits = parsed.get("hits", {}).get("hits", [])
                    except Exception as parse_err:
                        log.warning(f"JSON parse error: {parse_err}. Raw: {result[0].text}")
                        await asyncio.sleep(CHECK_INTERVAL)
                        continue

                    log.info(f"Retrieved {len(hits)} hits from position {from_position}")

                    if hits:
                        for hit in hits:
                            strelka_alert_queue.put(hit)
                        from_position += BATCH_SIZE
                        self.tracker.update_last_position(from_position)
                    else:
                        await asyncio.sleep(CHECK_INTERVAL)

                except Exception as e:
                    log.warning(f"Error retrieving alerts: {e}")
                    await asyncio.sleep(CHECK_INTERVAL)

        finally:
            await mcp.stop_client()

    def stop(self):
        self.stop_event.set()

class StrelkaProcessorThread(threading.Thread):
    def __init__(self, shared_tracker, stop_event):
        super().__init__()
        self.stop_event = stop_event
        self.tracker = shared_tracker
        self.log = logging.getLogger("__name__")

        # Create an AssemblylineConnector instance
        self.al = AssemblylineConnector(
            host=config["assemblyline"]["host"],
            user=config["assemblyline"]["user"],
            password=config["assemblyline"]["password"],
            queue="eviseek",
            verify=False
        )

    def run(self):
        while not self.stop_event.is_set():
            try:
                hit = strelka_alert_queue.get(timeout=5)
                asyncio.run(self.process_alert(hit))
            except queue.Empty:
                continue
            except Exception as e:
                self.log.error(f"Error processing alert: {e}")

    def stop(self):
        self.stop_event.set()

    async def process_alert(self, hit):
        alert_id = hit.get("_id")
        if not alert_id or self.tracker.alert_exists(alert_id):
            self.log.info(f"Skipping duplicate or missing alert_id: {alert_id}")
            return

        hit = hit.copy()
        _source = hit.get("_source", {})
        cleaned_source = self.clean_up_message_fields(_source)
        hit["_source"] = cleaned_source

        artifacts = self.extract_artifacts(cleaned_source)
        reports = []

        for artifact in artifacts:
            if artifact["type"] == "binary":
                path = artifact["path"]
                filename = os.path.basename(path)
                debug_path = f"/tmp/{filename}"

                try:
                    self.sftp_download_file(path, debug_path)
                    result = self.al.submit_and_collect(debug_path)
                    if result:
                        reports.append({"assemblyline_report": result})
                except Exception as e:
                    self.log.error(f"Failed to handle file {filename}: {e}")
                finally:
                    if os.path.exists(debug_path):
                        os.unlink(debug_path)

        alert_doc = {
            "alert_id": alert_id,
            "index": hit.get("_index"),
            "timestamp": datetime.utcnow().isoformat(),
            "casefile": {
                "so_alert": hit,
                "reports": reports,
                "artifacts": artifacts,
                "tags": [],
                "notes": ""
            }
        }
        self.tracker.save_alert(alert_doc)

    def clean_up_message_fields(self, doc):
        try:
            if isinstance(doc.get("message"), str):
                doc["message"] = json.loads(doc["message"])
        except Exception:
            doc["message"] = {}

        try:
            if isinstance(doc.get("network", {}).get("data", {}).get("decoded"), str):
                decoded_str = doc["network"]["data"]["decoded"]
                doc["network"]["data"]["decoded"] = decoded_str.encode('utf-8', 'ignore').decode('unicode_escape')
        except Exception:
            pass

        return doc

    def extract_artifacts(self, source):
        artifacts = []
        message = json.loads(json.dumps(source.get("message", {})))
        capture_path = message.get("capture_file")
        if capture_path:
            artifacts.append({"type": "pcap", "path": capture_path})

        request = json.loads(json.dumps(source.get("request", {})))
        attributes = request.get("attributes", {})
        filename = attributes.get("filename")
        if filename and filename.startswith("/nsm/strelka/processed/"):
            artifacts.append({"type": "strelka", "path": filename})
            artifacts.append({"type": "binary", "path": filename})

        return artifacts

    def sftp_download_file(self, remote_path, local_path):
        transport = paramiko.Transport((SSH_HOST, SSH_PORT))
        transport.connect(username=SSH_USERNAME, password=SSH_PASSWORD)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            sftp.get(remote_path, local_path)
            self.log.info(f"SFTP downloaded {remote_path} to {local_path}")
        finally:
            sftp.close()
            transport.close()

if __name__ == "__main__":
    shared_tracker = AlertTracker()
    shared_stop_event = threading.Event()
    alert_thread = AlertIngestorThread(shared_tracker, stop_event=shared_stop_event)
    alert_thread.daemon = True
    strelka_thread = StrelkaProcessorThread(shared_tracker, stop_event=shared_stop_event)
    strelka_thread.daemon = True

    alert_thread.start()
    strelka_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutdown requested. Stopping threads...")
        alert_thread.stop()
        strelka_thread.stop()
        alert_thread.join()
        strelka_thread.join()
        log.info("Ingestor and processor threads stopped.")