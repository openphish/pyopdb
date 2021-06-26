#!/usr/bin/env python3
import sqlite3
import argparse
import configparser
import os
import urllib.parse
import ntpath
import re
import json
import hashlib
import tempfile
import tarfile
import shutil
import boto3
import requests
import ipaddress

def api_result(success: bool, data: dict=None, msg: str=None):
    return {"success": success, "message": msg, "data": data}

def prepare_url(url: str):
    """Prepares URL for querying the url_norm field"""
    if not url:
        return None

    scheme, host, path, params, _, _ = urllib.parse.urlparse(url)
    # URLs that do not start with http are considered invalid
    if ':' in url and not url.lower().startswith('http'):
        return None

    # URLs without a scheme or a host are invalid
    if not scheme or not host:
        return None

    # Encode IDNA hostnames
    host = host.encode('idna').decode('ascii')

    path = re.sub("/{2,}", "/", path)
    direcotory, page = ntpath.split(path)
    page_name, page_ext = os.path.splitext(page)
    # replace common index pages with '/'
    if page and page_name.lower() in ['index', 'default']:
        if direcotory != '/':
            path = direcotory + '/'
        else:
            path = '/'

    if not path:
        path = '/'
    elif not page_ext and path[-1] != '/':
        path = path + '/'

    parts = [scheme, host, path, params, None, None]
    return requests.utils.requote_uri(urllib.parse.urlunparse(parts))

class OPDB():
    def __init__(self, cfg_file="./opdb.ini"):
        self._cfg_file = cfg_file
        self._config = dict()
        self._localdb_hash = None
        self._db_connection = None
        self._db_cursor = None

        self._load_config()
        self._load_db()

    @classmethod
    def _checksum(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                h.update(block)
        return h.hexdigest()

    def _load_db(self):
        """Load local database"""
        self._db_path = self._config.get('settings', {}).get('local_db_path')
        if not self._db_path:
            raise ValueError("local_db_path is not set in config file")

        if not os.path.exists(self._db_path):
            return

        self._localdb_hash = self._checksum(self._db_path)
        self._db_connection = sqlite3.connect(self._db_path)
        self._db_cursor = self._db_connection.cursor()

    def _load_config(self):
        """Read configuration file"""
        if not os.path.isfile(self._cfg_file):
            raise FileNotFoundError(self._cfg_file)
        elif not os.access(self._cfg_file, os.R_OK):
            raise PermissionError("Cannot read {}".format(self._cfg_file))
        elif os.stat(self._cfg_file).st_size == 0:
            raise IOError("Config file {} is empty".format(self._cfg_file))

        config = configparser.ConfigParser()
        config.read(self._cfg_file)
        sections = config.sections()
        for section in sections:
            self._config[section] = dict(config.items(section))

    def update(self):
        """Update the local database with a remote copy"""
        dblicense = self._config.get('license', {})
        if not dblicense:
            return api_result(False, msg="No license section in config file")

        api_key = dblicense.get('access_key')
        secret_key = dblicense.get('secret_key')
        if not api_key or not secret_key:
            return api_result(False, msg="API keys are not set in config file")

        try:
            bucket, level = dblicense.get('type', '').split(':')
        except ValueError:
            return api_result(False, msg="Invalid license type")

        if not bucket or not level:
            return api_result(False, msg="Invalid license type")

        remote_db_path = "{}.db.tgz".format(level)
        s3_client = boto3.client(
            's3',
            aws_access_key_id=api_key,
            aws_secret_access_key=secret_key)

        # Get metadata of remote database
        try:
            response = s3_client.head_object(Bucket=bucket, Key=remote_db_path)
        except Exception as e:
            return api_result(False, msg=str(e))
        if not response or response.get("ResponseMetadata") is None:
            return api_result(False, msg="Invalid HEAD response from server")

        remote_hash = (response.get("ResponseMetadata")
                       .get("HTTPHeaders", {})
                       .get("x-amz-meta-opdb-checksum", None))
        if not remote_hash:
            return api_result(False, msg="No checksum in headers from server")

        # Check if local database needs to be updated
        if self._localdb_hash == remote_hash:
            return api_result(True, msg="DB is up to date")

        # Download the new database to a temporary file
        temp = tempfile.NamedTemporaryFile(prefix="opdb_")
        s3_client.download_file(bucket, remote_db_path, temp.name)
        if not os.path.exists(temp.name):
            return api_result(False, msg="Failed to download remote db")

        # Extract the new database and replace the existing one
        with tempfile.TemporaryDirectory() as tmpdirname:
            try:
                tar = tarfile.open(temp.name, 'r:gz')
                tar.extractall(tmpdirname)
            except Exception as e:
                return api_result(False, error=str(e))
            new_db = os.path.join(tmpdirname, level + ".db")
            # Verify checksum against remote checksum
            if self._checksum(new_db) != remote_hash:
                return api_result(False, 
                    msg="Failed to verify remote db integrity")
            shutil.move(new_db, self._db_path)

        # Reload the database
        self._load_db()

        return api_result(True, msg="DB updated successfully")

    def run_query(self, q: str, *args):
        """Run a custom query"""
        if not self._db_connection or not self._db_cursor:
            return api_result(False, msg="OPDB is not initialized")

        if not q:
            return api_result(False, msg="Invalid query")

        try:
            self._db_cursor.execute(q, args)
        except sqlite3.OperationalError as e:
            return api_result(False, msg=str(e))

        return api_result(True, data=self._db_cursor.fetchall())

def check_url(opdb: OPDB, url: str):
    """Basic search to check if a URL is phishing"""
    if not isinstance(opdb, OPDB) or not url:
        raise TypeError("Invalid arguments")

    if not url.lower().startswith("http"):
        return api_result(False, msg="URL must start with http/https")

    url = prepare_url(url)
    if not url:
        return api_result(False, msg="URL is invalid")

    query = ("SELECT isotime, brand FROM phishing_urls WHERE url_norm = ? "
             "ORDER BY isotime DESC LIMIT 1")
    result = opdb.run_query(query, url)
    if not result["success"]:
        return result

    if not result["data"]:
        return api_result(True, msg="Not a phishing URL")

    url_entry = result["data"][0]
    response = {"discovery_date": url_entry[0], "brand": url_entry[1]}
    return api_result(True, data=response, msg="Phishing URL")

def check_ip(opdb: OPDB, ip: str):
    """Basic search to check if phishing URLs exist on an IP address"""
    if not isinstance(opdb, OPDB) or not ip:
        raise TypeError("Invalid arguments")

    try:
        ipaddr = ipaddress.ip_address(ip)
        if ipaddr.version != 4:
            return api_result(False, msg="IP is not IPv4")
    except ValueError:
        return api_result(False, msg="Invalid IP address")

    result = opdb.run_query(
        "SELECT DISTINCT url FROM phishing_urls WHERE ip = ?", ip)
    if not result["success"]:
        return result

    if not result["data"]:
        return api_result(True, msg="No phishing URLs")

    return api_result(True, data={"url": [r[0] for r in result["data"]]})

def check_hostname(opdb: OPDB, hostname: str):
    """Basic fuzzy match to check for phishing URLs on a hostname"""
    if not isinstance(opdb, OPDB) or not hostname:
        raise TypeError("Invalid arguments")

    result = opdb.run_query(
        "SELECT DISTINCT host FROM phishing_urls WHERE host LIKE ?",
        "%{}%".format(hostname))
    if not result["success"]:
        return result

    if not result["data"]:
        return api_result(True, msg="No URLs on hostname")

    return api_result(True, data={"hosts": [r[0] for r in result["data"]]})

if __name__ == "__main__":
    cli_handler = argparse.ArgumentParser()
    cli_handler.add_argument(
        "--checkurl",
        help="check if URL is phishing",
        type=str,
        nargs=1)
    cli_handler.add_argument(
        "--checkip",
        help="check for phishing URLs on IPv4",
        type=str,
        nargs=1)
    cli_handler.add_argument(
        "--checkhost",
        help="check for phishing URLs on hostname",
        type=str,
        nargs=1)
    cli_handler.add_argument(
        "--update",
        help="update phishing db",
        action="store_true"
    )
    cli_handler.add_argument(
        "--config",
        help="config file path",
        type=str
    )

    result = None
    args = cli_handler.parse_args()
    if args.config:
        opdb = OPDB(cfg_file=args.config)
    else:
        opdb = OPDB()

    if args.checkurl:
        result = check_url(opdb, args.checkurl[0])
    elif args.checkip:
        result = check_ip(opdb, args.checkip[0])
    elif args.checkhost:
        result = check_hostname(opdb, args.checkhost[0])
    elif args.update:
        result = opdb.update()
    else:
        cli_handler.print_help()

    if result:
        print(json.dumps(result, indent=2))