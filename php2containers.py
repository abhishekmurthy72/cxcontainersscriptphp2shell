#!/usr/bin/env python3
"""
cx1_php_container_packages.py

Checkmarx One: for every project, find the latest scan and query the
Containers "buffet" GraphQL API for packages whose name contains "php".

Inputs (CLI flags or environment variables):
  --base-url      / CX1_URL            e.g. https://eu.ast.checkmarx.net
  --tenant        / CX1_TENANT         tenant (realm) name
  Auth, one of:
    --api-key     / CX1_API_KEY        Checkmarx One API key (refresh token)
    --client-id   / CX1_CLIENT_ID  +  --client-secret / CX1_CLIENT_SECRET   (OAuth client)
  Optional:
    --iam-url     / CX1_IAM_URL        override IAM URL (default: derived from base URL)
    --package     text to search for in package names (default: php)
    --any-scan    use the latest scan even if it did not run the containers engine
    --out         output file prefix (default: php_container_packages)

Examples:
  python cx1_php_container_packages.py --base-url https://ast.checkmarx.net \
      --tenant mytenant --api-key "$KEY"

  python cx1_php_container_packages.py --base-url https://eu.ast.checkmarx.net \
      --tenant mytenant --client-id my-client --client-secret "$SECRET"
"""

import argparse
import csv
import json
import os
import sys
import time
from urllib.parse import urlparse, urlunparse

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")


GRAPHQL_QUERY = (
    "query FindPhpPackages($scanId: String!) { "
    "packagesByScan(scanId: $scanId, skip: 0, take: 1000, "
    "where: { packageName: { contains: \"%s\" } }) { "
    "totalCount items { packageName packageVersion type distribution "
    "runtimeUsage vulnerabilitiesCount images { imageName imageTag } } } }"
)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
def derive_iam_url(base_url: str) -> str:
    """https://eu.ast.checkmarx.net -> https://eu.iam.checkmarx.net"""
    p = urlparse(base_url)
    host = p.netloc
    if ".ast." in host:
        host = host.replace(".ast.", ".iam.", 1)
    elif host.startswith("ast."):
        host = "iam." + host[len("ast."):]
    return urlunparse((p.scheme, host, "", "", "", ""))


class Cx1Client:
    def __init__(self, base_url, tenant, iam_url=None, api_key=None,
                 client_id=None, client_secret=None, timeout=60):
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.iam_url = (iam_url or derive_iam_url(self.base_url)).rstrip("/")
        self.api_key = api_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.session = requests.Session()
        self.token = None
        self.token_expiry = 0
        self.authenticate()

    # -- token ------------------------------------------------------------- #
    def authenticate(self):
        url = f"{self.iam_url}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        if self.api_key:
            data = {"grant_type": "refresh_token",
                    "client_id": "ast-app",
                    "refresh_token": self.api_key}
        elif self.client_id and self.client_secret:
            data = {"grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret}
        else:
            raise ValueError("Provide --api-key or --client-id/--client-secret")

        r = self.session.post(url, data=data, timeout=self.timeout)
        if r.status_code != 200:
            raise RuntimeError(f"Auth failed ({r.status_code}) at {url}: {r.text[:300]}")
        body = r.json()
        self.token = body["access_token"]
        self.token_expiry = time.time() + int(body.get("expires_in", 1800)) - 60

    def _headers(self, extra=None):
        if time.time() >= self.token_expiry:
            self.authenticate()
        h = {"Authorization": f"Bearer {self.token}",
             "Accept": "application/json; version=1.0",
             "Content-Type": "application/json"}
        if extra:
            h.update(extra)
        return h

    # -- generic request with retries ------------------------------------- #
    def request(self, method, path, params=None, json_body=None, headers=None, retries=4):
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        for attempt in range(retries + 1):
            r = self.session.request(method, url, params=params, json=json_body,
                                     headers=self._headers(headers), timeout=self.timeout)
            if r.status_code == 401 and attempt == 0:
                self.authenticate()
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = float(r.headers.get("Retry-After", 2 ** attempt))
                time.sleep(min(wait, 30))
                continue
            return r
        return r

    # -- projects ---------------------------------------------------------- #
    def list_projects(self, page_size=100):
        projects, offset = [], 0
        while True:
            r = self.request("GET", "/api/projects",
                             params={"offset": offset, "limit": page_size})
            r.raise_for_status()
            body = r.json()
            batch = body.get("projects", [])
            projects.extend(batch)
            total = body.get("filteredTotalCount") or body.get("totalCount") or 0
            offset += len(batch)
            if not batch or offset >= total:
                break
        return projects

    # -- scans ------------------------------------------------------------- #
    def latest_scan(self, project_id, require_containers=True, lookback=25):
        """
        Return (scan, engines) for the newest completed scan of the project.
        If require_containers, prefer the newest scan that ran the containers engine.
        """
        r = self.request("GET", "/api/scans",
                         params={"project-id": project_id,
                                 "limit": lookback,
                                 "sort": "-created_at"})
        r.raise_for_status()
        scans = r.json().get("scans", [])
        completed = [s for s in scans if s.get("status") in ("Completed", "Partial")]
        if not completed:
            return None, []

        def engines_of(s):
            eng = set(s.get("engines") or [])
            for sd in s.get("statusDetails") or []:
                if sd.get("status") == "Completed":
                    eng.add(sd.get("name"))
            return sorted(e for e in eng if e)

        if require_containers:
            for s in completed:
                eng = engines_of(s)
                if "containers" in eng:
                    return s, eng
        return completed[0], engines_of(completed[0])

    # -- containers GraphQL ----------------------------------------------- #
    def find_packages(self, project_id, scan_id, needle="php"):
        payload = {"query": GRAPHQL_QUERY % needle,
                   "variables": {"scanId": scan_id}}
        r = self.request("POST", "/api/containers/buffet/graphql-V2",
                         json_body=payload,
                         headers={"Cx-Project-Id": project_id})
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}: {r.text[:200]}"
        body = r.json()
        if body.get("errors"):
            return None, "; ".join(e.get("message", str(e)) for e in body["errors"])
        data = (body.get("data") or {}).get("packagesByScan") or {}
        return data, None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.getenv("CX1_URL"), help="Checkmarx One URL")
    ap.add_argument("--tenant", default=os.getenv("CX1_TENANT"), help="Tenant name")
    ap.add_argument("--iam-url", default=os.getenv("CX1_IAM_URL"), help="Override IAM URL")
    ap.add_argument("--api-key", default=os.getenv("CX1_API_KEY"))
    ap.add_argument("--client-id", default=os.getenv("CX1_CLIENT_ID"))
    ap.add_argument("--client-secret", default=os.getenv("CX1_CLIENT_SECRET"))
    ap.add_argument("--package", default="php", help="Substring to match in package names")
    ap.add_argument("--any-scan", action="store_true",
                    help="Use latest scan even if the containers engine did not run")
    ap.add_argument("--out", default="php_container_packages", help="Output file prefix")
    a = ap.parse_args()
    if not a.base_url or not a.tenant:
        ap.error("--base-url and --tenant are required (or CX1_URL / CX1_TENANT)")
    if not a.api_key and not (a.client_id and a.client_secret):
        ap.error("Provide --api-key or both --client-id and --client-secret")
    return a


def main():
    args = parse_args()
    client = Cx1Client(args.base_url, args.tenant, args.iam_url,
                       args.api_key, args.client_id, args.client_secret)
    print(f"Authenticated to {client.base_url} (IAM: {client.iam_url})")

    projects = client.list_projects()
    print(f"Found {len(projects)} projects")

    results = []        # one row per project
    package_rows = []   # one row per matching package

    for i, p in enumerate(projects, 1):
        pid, pname = p["id"], p.get("name", "")
        row = {"projectId": pid, "projectName": pname, "scanId": None,
               "scanDate": None, "engines": "", "containersScanned": False,
               "phpPackageCount": 0, "error": None}
        try:
            scan, engines = client.latest_scan(pid, require_containers=not args.any_scan)
            if not scan:
                row["error"] = "no completed scans"
            else:
                row["scanId"] = scan["id"]
                row["scanDate"] = scan.get("createdAt")
                row["engines"] = ",".join(engines)
                row["containersScanned"] = "containers" in engines
                if row["containersScanned"] or args.any_scan:
                    data, err = client.find_packages(pid, scan["id"], args.package)
                    if err:
                        row["error"] = err
                    else:
                        items = data.get("items") or []
                        row["phpPackageCount"] = data.get("totalCount", len(items))
                        for it in items:
                            images = it.get("images") or []
                            package_rows.append({
                                "projectId": pid, "projectName": pname,
                                "scanId": scan["id"],
                                "packageName": it.get("packageName"),
                                "packageVersion": it.get("packageVersion"),
                                "type": it.get("type"),
                                "distribution": it.get("distribution"),
                                "runtimeUsage": it.get("runtimeUsage"),
                                "vulnerabilitiesCount": it.get("vulnerabilitiesCount"),
                                "images": ";".join(
                                    f"{im.get('imageName')}:{im.get('imageTag')}" for im in images),
                            })
                else:
                    row["error"] = "latest scan has no containers results"
        except Exception as e:  # keep going on per-project failures
            row["error"] = str(e)[:200]

        results.append(row)
        status = (f"{row['phpPackageCount']} {args.package} pkgs" if row["phpPackageCount"]
                  else (row["error"] or f"no {args.package} pkgs"))
        print(f"[{i}/{len(projects)}] {pname[:50]:<50} scan={row['scanId'] or '-':<36} {status}")

    # -- write outputs ----------------------------------------------------- #
    with open(f"{args.out}_projects.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else ["projectId"])
        w.writeheader()
        w.writerows(results)

    pkg_fields = ["projectId", "projectName", "scanId", "packageName", "packageVersion",
                  "type", "distribution", "runtimeUsage", "vulnerabilitiesCount", "images"]
    with open(f"{args.out}_packages.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=pkg_fields)
        w.writeheader()
        w.writerows(package_rows)

    with open(f"{args.out}.json", "w", encoding="utf-8") as f:
        json.dump({"projects": results, "packages": package_rows}, f, indent=2)

    hits = [r for r in results if r["phpPackageCount"]]
    print("\n=== Summary ===")
    print(f"Projects scanned:              {len(results)}")
    print(f"Projects with containers scan: {sum(r['containersScanned'] for r in results)}")
    print(f"Projects with '{args.package}' packages: {len(hits)}")
    for r in hits:
        print(f"  - {r['projectName']} ({r['phpPackageCount']} packages, scan {r['scanId']})")
    print(f"\nWritten: {args.out}_projects.csv, {args.out}_packages.csv, {args.out}.json")


if __name__ == "__main__":
    main()
