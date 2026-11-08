
import json

with open("logs/audit.jsonl", "r", encoding="utf-8") as file:
    for line in file:
        event = json.loads(line)

        # 1. 로그 정보 추출
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        status = event.get("responseStatus", {}).get("code")

        # 2. 사용자 정보 추출
        user = event.get("user", {}).get("username")
        impersonated_user = event.get(
            "impersonatedUser", {}
        ).get("username")

        # 3. 탐지 조건
        if verb == "list" and resource == "secrets":
            print(
                f"[A001] Secret 목록 조회 | "
                f"사용자={impersonated_user or user} | "
                f"결과={status}"
            )

        elif verb == "create" and resource == "clusterrolebindings":
            print(
                f"[A002] ClusterRoleBinding 생성 시도 | "
                f"사용자={impersonated_user or user} | "
                f"결과={status}"
            )
