# k8s-serviceaccount-threat-detection
Kubernetes ServiceAccount credential access and privilege escalation attempt detection using Falco, Audit Logs, and Python correlation analysis.

# Kubernetes ServiceAccount 자격증명 접근 및 권한 상승 시도 탐지

> **Falco + Kubernetes Audit Log + Python 상관분석**  
> 로컬 Kubernetes 실습 환경에서 ServiceAccount 토큰 파일 접근과 뒤이은 Kubernetes API 요청을 수집하고, 계정·시간·순서를 기준으로 연관성을 분석합니다.

## 1. 프로젝트 개요

Kubernetes의 ServiceAccount 토큰은 Pod가 API 서버에 인증할 때 사용되는 자격증명입니다. 해당 토큰 파일에 접근한 뒤 Secret 목록 조회나 RBAC 권한 변경 요청이 이어진다면 조사가 필요할 수 있습니다.

이 프로젝트는 다음 세 이벤트를 연결하는 탐지입니다.

| ID | 데이터 소스 | 탐지 대상 | 실습에서 관찰한 결과 |
| --- | --- | --- | --- |
| **F001** | Falco (syscall) | Pod에서 `/var/run/secrets/kubernetes.io/serviceaccount/token` 읽기 | 탐지 확인 |
| **A001** | Kubernetes Audit Log | `list` 요청, 대상 `secrets` | `403 Forbidden` |
| **A002** | Kubernetes Audit Log | `create` 요청, 대상 `clusterrolebindings` | `403 Forbidden` |

**범위 및 해석:** A001·A002는 `kubectl --as`를 이용해 ServiceAccount 권한을 가장(impersonation)한 테스트입니다. 실제 탈취 토큰으로 API를 호출한 것이 아니며, 권한 상승도 성공하지 않았습니다. 따라서 이 프로젝트가 입증하는 것은 **감사 이벤트 수집과 탐지·상관분석 로직의 동작**이지, 실제 침해나 토큰 악용의 입증이 아닙니다.

## 2. 아키텍처

```text
                       [Kubernetes kind 클러스터]
                                  |
            +---------------------+---------------------+
            |                                           |
   [payment-api-7d9 Pod]                       [Kubernetes API 서버]
   ServiceAccount: sihyeon                       Audit Policy: Metadata
            |                                           |
   토큰 파일 읽기 (F001)                       API 요청 감사 기록
            |                                    A001 / A002
            v                                           v
      [Falco 로그]                              [audit.log]
            |                                           |
            v                                           v
      logs/falco.log                           logs/audit.jsonl
            +---------------------+---------------------+
                                  |
                          [correlation_v2.py]
                                  |
                      Pod -> ServiceAccount 매핑
                      + 동일 계정 및 이벤트 순서
                      + 1분 / 5분 / 30분 시간 범위
                                  |
                         [상관분석 결과 출력]
```

## 3. 실습 환경

- 장비: Apple Silicon MacBook Air (ARM64)
- 가상화 및 로컬 컨테이너: Colima, Docker
- Kubernetes: kind 클러스터 / `kubectl` 컨텍스트 `kind-toss-security-arm`
- 예시 네임스페이스: `payment`
- 예시 Pod: `payment-api-7d9`
- 예시 ServiceAccount: `sihyeon`
- Falco: Helm으로 배포, Modern eBPF 드라이버 사용
- 분석 언어: Python 3 (표준 라이브러리의 `json`, `datetime`, `subprocess` 사용)



## 4. 프로젝트 파일 구조

```text
toss-k8s-security_fin/
├── README.md
├── audit_detector.py           # A001/A002 개별 Audit Log 탐지
├── correlation.py              # 초기 상관분석 구현
├── correlation_v2.py           # 시간 범위 비교 및 A002 이벤트 묶음
├── .gitignore                  # 원본 로그 및 인증정보 제외 (추가 권장)
├── falco/
│   └── rules.yaml              # Falco F001 규칙
├── k8s/
│   ├── pod.yaml
│   ├── secret-reader-role.yaml
│   ├── secret-reader-binding.yaml
│   └── audit-policy.yaml
└── logs/                        # 로컬 수집 데이터; GitHub 업로드 제외
    ├── falco.log
    └── audit.jsonl
```



## 5. 탐지 조건

### F001 — ServiceAccount 토큰 파일 접근

- Falco의 파일 읽기 이벤트(`open_read`)를 관찰합니다.
- 대상 경로: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- 상관분석에서는 Pod와 Namespace 정보가 식별되는 이벤트를 사용합니다.
- `container.id == "host"` 또는 Pod 정보 누락 이벤트는 **현재 상관분석에서 제외**합니다. 제외된 이벤트가 안전하다는 뜻은 아닙니다.

### A001 — Secret 목록 조회

Audit Log에서 다음 항목을 확인합니다.

```text
verb == "list"
objectRef.resource == "secrets"
```

### A002 — ClusterRoleBinding 생성 시도

```text
verb == "create"
objectRef.resource == "clusterrolebindings"
```

A001·A002 모두 `stage == "ResponseComplete"`를 사용해 최종 응답 코드를 확인합니다. `403`은 요청 거부, `201`은 리소스 생성 성공을 의미합니다. 단, `201`이더라도 실제로 어떤 권한이 누구에게 연결됐는지 확인해야 합니다.

### 이벤트 상관분석 조건

1. **동일 ServiceAccount:** F001 Pod의 ServiceAccount와 A001·A002 요청 주체가 동일한지 비교
2. **동일 클러스터:** 본 PoC에서는 모든 입력 로그가 동일한 `kind-toss-security-arm` 클러스터에서 수집됐다고 전제
3. **발생 순서:** `F001 <= A001 <= A002`
4. **시간 범위:** `A002.time - F001.time`이 설정된 범위(1분·5분·30분) 이내
5. **응답 결과:** A001·A002의 HTTP 상태 코드를 출력해 요청 시도와 성공을 구분


## 6. 실행 방법

### 6.1 필수 환경 확인

Mac 터미널에서 실습 클러스터와 Pod를 확인합니다.

```bash
kubectl --context kind-toss-security-arm get pods -n payment
kubectl --context kind-toss-security-arm get pods -n falco
kubectl --context kind-toss-security-arm get pod payment-api-7d9 \
  -n payment -o jsonpath='{.spec.serviceAccountName}{"\n"}'
```


### 6.2 실습 이벤트 생성

**F001 — Pod 내 토큰 파일 접근 (토큰 값은 출력하지 않음)**

```bash
kubectl --context kind-toss-security-arm \
  exec -n payment payment-api-7d9 -- \
  sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null'
```

**A001 — Secret 목록 조회 시도 (403)**

```bash
kubectl --context kind-toss-security-arm \
  --as=system:serviceaccount:payment:sihyeon \
  get secrets -n payment
```

**A002 — ClusterRoleBinding 생성 시도 (403)**

```bash
kubectl --context kind-toss-security-arm \
  --as=system:serviceaccount:payment:sihyeon \
  create clusterrolebinding finance-admin-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=payment:sihyeon
```


### 6.3 로그 수집

프로젝트 최상위 폴더에서 실행합니다.

```bash
mkdir -p logs

kubectl --context kind-toss-security-arm \
  -n falco logs daemonset/falco --tail=-1 > logs/falco.log

docker cp \
  toss-security-arm-control-plane:/var/log/kubernetes/audit.log \
  logs/audit.jsonl
```

Falco 로그에는 비JSON 메시지가 섞일 수 있어 Python 코드에서 JSON 변환 오류를 건너뜁니다. 수집된 파일은 **해당 시점의 스냅샷**이므로 이벤트를 다시 발생시켰다면 다시 수집해야 합니다.

### 6.4 탐지 프로그램 실행

```bash
python3 audit_detector.py
python3 correlation_v2.py
```

`correlation_v2.py`는 로컬 파일을 읽고 `kubectl`로 Pod의 현재 ServiceAccount를 조회합니다. 따라서 클러스터 연결이 필요합니다.

## 7. 실제 실험 결과

<img width="830" height="235" alt="스크린샷 2026-11-09 01 28 48" src="https://github.com/user-attachments/assets/2e1fccc8-9e3f-4156-852b-4e0ca8a96d07" />

수집한 실습 로그에서는 F001 이벤트 3건, A001/A002 API 이벤트 5건을 확인했습니다. 이 가운데 상관분석 조건에 맞는 흐름을 묶은 결과는 아래와 같습니다.

<img width="676" height="342" alt="스크린샷 2026-11-09 03 27 08" src="https://github.com/user-attachments/assets/d5b14363-b46a-4b18-a7e7-b8bb2db23408" />

| 시간 조건 | 상관분석 경고 |
| --- | ---: |
| **1분** | 0건 |
| **5분** | 0건 |
| **30분** | **1건** |

**30분 기준으로 연결된 대표 이벤트 (UTC)**

| 이벤트 | 시각 | 응답 |
| --- | --- | --- |
| F001 — 토큰 파일 접근 | 2026-11-08 15:03:22 | Falco 탐지 |
| A001 — Secret 목록 조회 | 2026-11-08 15:06:39 | 403 |
| A002 — ClusterRoleBinding 생성 시도 | 2026-11-08 15:19:15 | 403 |
| A002 — ClusterRoleBinding 생성 시도 | 2026-11-08 15:29:30 | 403 |

- 대상: `payment-api-7d9`, `system:serviceaccount:payment:sihyeon`
- 첫 F001부터 첫 A002까지 약 **15분 54초**, 두 번째 A002까지 약 **26분 8초**
- 동일한 F001·A001 흐름에 A002 두 건이 연결되어 **경고 1건으로 묶음**
- A001·A002는 `impersonatedUser`가 기록된 **사용자 가장 테스트 요청**
- 두 A002 모두 `403`으로 차단되어 **관리자 권한 부여는 성공하지 않음**

이 결과는 **30분이 최적의 탐지 시간이라는 증거가 아닙니다.** 이번 테스트 데이터에서 30분 조건일 때 해당 조합이 연결됐다는 실험 결과입니다.

## 8. 탐지 시간 기준에 대한 해석
본 프로젝트에서는 동일한 Kubernetes 클러스터와 ServiceAccount에서 F001(토큰 접근) → A001(Secret 목록 조회) → A002(ClusterRoleBinding 생성 시도)가 순서대로 발생하고, 첫 번째 이벤트부터 마지막 이벤트까지의 시간이 
**30분 이내인 경우 하나의 연관된 공격 의심 시나리오로 판단**하도록 탐지 조건을 설정하였습니다.

이를 통해 개별 보안 이벤트를 단순 탐지하는 것을 넘어, 일정 시간 내에 발생한 연속적인 행위를 상관분석하여 잠재적인 권한 상승 시도를 식별하도록 구현하였습니다.


참고할 만한 공식 자료:

- [MITRE ATT&CK — Kubernetes 관련 탐지 전략 DET0198](https://attack.mitre.org/detectionstrategies/DET0198/)
- [Elastic — Service Account Token or Certificate Access Followed by Kubernetes API Request](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/cross-platform/execution_d4c_k8s_mda_service_account_token_access_followed_by_kubernetes_api_request)



## 9. 비용 및 운영 방식

### 9.1 현재 구현 환경: MacBook 로컬 PoC


| 항목 | 사용 기술 | 추가 클라우드 요금 |
| --- | --- | ---: |
| 로컬 가상화 및 컨테이너 | Colima, Docker | 0원 |
| Kubernetes 클러스터 | kind | 0원 |
| 런타임 이벤트 탐지 | Falco (오픈소스) | 0원 |
| API 감사 로그 | Kubernetes Audit Policy | 0원 |
| 로그 상관분석 | Python 표준 라이브러리 | 0원 |
| 결과 보관 | 로컬 파일 (`logs/`) | 0원 |
| **현재 환경 합계** | **별도 유료 클라우드 리소스 미사용** | **0원** |


### 9.2 AWS EKS로 확장할 경우 (선택사항, 현재 미구현)

AWS 공식 EKS 요금표 기준, **표준 지원 Kubernetes 버전의 EKS 클러스터 기본 요금은 $0.10/시간**입니다. 클러스터 1개를 한 달 730시간 운영한다는 *가정*을 적용하면 **$73/월**입니다.
| 추가 과금 항목 | 비고 |
| --- | --- |
| EKS 클러스터 기본료 | $0.10/시간 × 730시간 = **$73/월** (표준 지원 가정) |
| 워커 노드(EC2 또는 Fargate) | 별도 과금, 인스턴스 유형·가동 시간·리전에 따라 변동 |
| EBS 및 로그 저장소 | 사용량에 따라 별도 과금 |
| 외부 네트워크, NAT, 로드 밸런서, 공인 IPv4 | 구성 및 트래픽에 따라 별도 과금 가능 |
| CloudWatch 등 관측 도구 | 사용 시 별도 과금 가능 |

- [AWS 공식 EKS 요금](https://aws.amazon.com/eks/pricing/)
- [AWS 공식 EC2 온디맨드 요금](https://aws.amazon.com/ec2/pricing/on-demand/)
- [AWS Pricing Calculator](https://calculator.aws/)


## 10. 구현 진행 내역

| 단계 | 실제 수행 내용 | 확인 결과 |
| --- | --- | --- |
| 1. 실행 환경 구축 | MacBook ARM64에서 Colima·kind 클러스터 준비 | 로컬 실습 환경 구성 |
| 2. RBAC 구성 | `payment` 네임스페이스, `sihyeon` ServiceAccount 및 `secret-reader` Role/RoleBinding 구성 | 제한된 Secret 조회 권한 적용 |
| 3. Falco 탐지 | Helm으로 Falco 배포 후 `rules.yaml`의 F001 적용 | Pod의 토큰 파일 접근 감지 |
| 4. 감사 정책 설정 | API 서버에 `audit-policy.yaml`, 감사 로그 파일 설정 | `audit.log` 생성 및 API 이벤트 확인 |
| 5. API 시도 재현 | `--as`로 Secret 목록 조회와 ClusterRoleBinding 생성 요청 | A001·A002 모두 403 거부 확인 |
| 6. Python 단일 이벤트 탐지 | `audit_detector.py`로 A001·A002 분류 | 실제 수집 로그에서 탐지 |
| 7. 상관분석 구현 | `correlation.py`에서 Pod→SA 매핑 및 시간·계정·순서 비교 | 30분 내 관련 흐름 확인 |
| 8. 개선 및 비교 | `correlation_v2.py`에서 A002 묶음, 1·5·30분 비교 | **0건 / 0건 / 1건** |
| 9. 문서화 | GitHub README에 아키텍처·절차·실험 결과·비용·한계 명시 | 현재 문서 |

