
import json
import subprocess
from datetime import datetime, timedelta, timezone

CLUSTER = "kind-toss-security-arm"


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_jsonl(path):
    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


# Pod가 사용하는 ServiceAccount 조회
def get_service_account(namespace, pod):
    try:
        result = subprocess.check_output(
            [
                "kubectl", "--context", CLUSTER,
                "get", "pod", pod,
                "-n", namespace,
                "-o", "jsonpath={.spec.serviceAccountName}"
            ],
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()

        return f"system:serviceaccount:{namespace}:{result or 'default'}"

    except subprocess.CalledProcessError:
        return None


# 1. Falco F001 추출
falco_events = []
sa_cache = {}

for event in read_jsonl("logs/falco.log"):
    if event.get("rule") != "F001_ServiceAccount_Token_Access":
        continue

    fields = event.get("output_fields") or {}
    pod = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name")
    container = fields.get("container.id")

    # Pod를 식별할 수 없는 host 이벤트 제외
    if not pod or not namespace or container == "host":
        continue

    key = (namespace, pod)

    if key not in sa_cache:
        sa_cache[key] = get_service_account(namespace, pod)

    sa = sa_cache[key]
    timestamp = parse_time(event.get("time"))

    if sa and timestamp:
        falco_events.append({
            "type": "F001",
            "sa": sa,
            "time": timestamp,
            "pod": pod
        })


# 2. Kubernetes Audit Log 추출
audit_events = []
seen_audit_ids = set()

for event in read_jsonl("logs/audit.jsonl"):
    if event.get("stage") != "ResponseComplete":
        continue

    verb = event.get("verb")
    obj = event.get("objectRef") or {}
    resource = obj.get("resource")

    if verb == "list" and resource == "secrets":
        rule = "A001"

    elif verb == "create" and resource == "clusterrolebindings":
        rule = "A002"

    else:
        continue

    audit_id = event.get("auditID")

    if audit_id and audit_id in seen_audit_ids:
        continue

    if audit_id:
        seen_audit_ids.add(audit_id)

    user = (event.get("user") or {}).get("username")
    impersonated = (
        (event.get("impersonatedUser") or {}).get("username")
    )

    sa = impersonated or user
    timestamp = parse_time(event.get("requestReceivedTimestamp"))
    status = (event.get("responseStatus") or {}).get("code")

    if not sa or not timestamp:
        continue

    audit_events.append({
        "type": rule,
        "sa": sa,
        "time": timestamp,
        "status": status,
        "impersonated": bool(impersonated),
        "resource": resource
    })

# 3. 시간 조건 설정
TIME_WINDOWS = {
    "1분": timedelta(minutes=1),
    "5분": timedelta(minutes=5),
    "30분": timedelta(minutes=30)
}

print(f"F001 이벤트: {len(falco_events)}건")
print(f"API 이벤트: {len(audit_events)}건")


def correlate(time_window):
    grouped = {}

    for f in falco_events:
        for a1 in audit_events:

            if a1["type"] != "A001":
                continue

            if f["sa"] != a1["sa"]:
                continue

            if f["time"] > a1["time"]:
                continue

            for a2 in audit_events:

                if a2["type"] != "A002":
                    continue

                if a1["sa"] != a2["sa"]:
                    continue

                if a1["time"] > a2["time"]:
                    continue

                if a2["time"] - f["time"] > time_window:
                    continue

                key = (f["sa"], f["time"], a1["time"])

                if key not in grouped:
                    grouped[key] = {
                        "f001": f,
                        "a001": a1,
                        "a002_events": []
                    }

                grouped[key]["a002_events"].append(a2)

    return list(grouped.values())
# 4. 시간별 탐지 결과 비교
for name, time_window in TIME_WINDOWS.items():
    results = correlate(time_window)

    print(f"\n===== {name} 탐지 결과 =====")
    print(f"상관분석 경고: {len(results)}건")

    for result in results:
        f = result["f001"]
        a1 = result["a001"]

        print("Cluster:", CLUSTER)
        print("ServiceAccount:", f["sa"])
        print("Pod:", f["pod"])
        print("F001:", f["time"])
        print("A001:", a1["time"])

        for a2 in result["a002_events"]:
            print("A002:", a2["time"], "status:", a2["status"])

        if a1["impersonated"] or any(
            a2["impersonated"] for a2 in result["a002_events"]
        ):
            print("판정: 사용자 가장 요청 포함 (실습 여부 확인)")
        else:
            print("판정: 권한 상승 의심 - 추가 조사 필요")
