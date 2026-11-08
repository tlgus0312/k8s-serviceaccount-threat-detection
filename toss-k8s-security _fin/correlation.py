
import json
import subprocess
from datetime import datetime, timedelta, timezone

CLUSTER = "kind-toss-security-arm"
WINDOW = timedelta(minutes=30)


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


# 3. 상관분석
print(f"F001 이벤트: {len(falco_events)}건")
print(f"API 이벤트(A001/A002): {len(audit_events)}건")

matches = []

print("\n===== F001 로그 =====")
for f in falco_events:
    print(f)

print("\n===== A001 / A002 로그 =====")
for a in audit_events:
    print(a)
for f in falco_events:
    for a1 in audit_events:
        if a1["type"] != "A001":
            continue

        if f["sa"] != a1["sa"]:
            continue

        if not f["time"] <= a1["time"]:
            continue

        for a2 in audit_events:
            if a2["type"] != "A002":
                continue

            # C1: 동일 ServiceAccount
            if a1["sa"] != a2["sa"]:
                continue

            # C3: 이벤트 순서
            if not a1["time"] <= a2["time"]:
                continue

            # C4: 30분 이내
            if a2["time"] - f["time"] > WINDOW:
                continue

            matches.append((f, a1, a2))


# 4. 탐지 결과 출력
if not matches:
    print("\n[INFO] 조건을 모두 충족하는 이벤트 조합 없음")

else:
    for f, a1, a2 in matches:
        is_test = a1["impersonated"] or a2["impersonated"]

        print("\n[CORRELATION] 이벤트 연관성 발견")
        print("Cluster:", CLUSTER)
        print("ServiceAccount:", f["sa"])
        print("Pod:", f["pod"])
        print("F001:", f["time"])
        print("A001:", a1["time"], "status =", a1["status"])
        print("A002:", a2["time"], "status =", a2["status"])

        if is_test:
            print("판정: 관리자 가장을 사용한 실습 시나리오")
        elif a2["status"] == 201:
            print("판정: 높은 위험 - 권한 연결 생성 성공")
        elif a2["status"] == 403:
            print("판정: 권한 상승 시도 의심 - RBAC 차단")
        else:
            print("판정: 추가 조사 필요")
