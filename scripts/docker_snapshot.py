import subprocess,json
p=subprocess.run(["docker","ps","--no-trunc","--format","{{json .}}"],capture_output=True,text=True)
if p.returncode: raise SystemExit(p.stderr.strip() or "Docker unavailable")
print(json.dumps({"source":"docker_read_only_snapshot","containers":[json.loads(x) for x in p.stdout.splitlines() if x.strip()]},indent=2))
