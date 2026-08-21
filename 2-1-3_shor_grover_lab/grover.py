from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit.primitives import StatevectorSampler


# 공개된 평문과 암호문
# 배열 순서는 [하위 비트, 상위 비트]
# Qiskit 출력은 반대로 상위 비트부터 표시한다.
P_BITS = [1, 0]    # P = 01
C_BITS = [0, 1]    # C = 10


# ---------------------------------------------------------
# Oracle: E_k(P) == C인 후보 키의 위상 반전
# ---------------------------------------------------------
def encryption_oracle(qc, key, work, phase):

    # 1. 작업 레지스터에 공개 평문 P 준비
    for i, bit in enumerate(P_BITS):
        if bit == 1:
            qc.x(work[i])

    # 2. 장난감 암호화: E_k(P) = P XOR k
    for i in range(2):
        qc.cx(key[i], work[i])

    # 현재 work에는 E_k(P)가 저장되어 있다.

    # 3. E_k(P) == C인지 비교
    # C의 비트가 0인 위치를 X로 반전하면,
    # 일치할 때 work가 |11>이 된다.
    for i, bit in enumerate(C_BITS):
        if bit == 0:
            qc.x(work[i])

    # work == |11>이면 phase 큐비트에 X 적용
    # phase가 |-> 상태이므로 후보 키의 위상이 반전된다.
    qc.ccx(work[0], work[1], phase[0])

    # 4. 비교 연산 되돌리기
    for i, bit in reversed(list(enumerate(C_BITS))):
        if bit == 0:
            qc.x(work[i])

    # 5. 암호화 연산 되돌리기
    for i in reversed(range(2)):
        qc.cx(key[i], work[i])

    # 6. 평문 준비 연산 되돌리기
    for i, bit in reversed(list(enumerate(P_BITS))):
        if bit == 1:
            qc.x(work[i])


# ---------------------------------------------------------
# 2큐비트 Grover diffuser
# ---------------------------------------------------------
def diffuser(qc, key):
    qc.h(key)
    qc.x(key)

    # |11>에 위상 반전
    qc.cz(key[0], key[1])

    qc.x(key)
    qc.h(key)


# ---------------------------------------------------------
# 전체 회로
# ---------------------------------------------------------
key = QuantumRegister(2, "key")
work = QuantumRegister(2, "cipher")
phase = QuantumRegister(1, "phase")
result = ClassicalRegister(2, "result")

qc = QuantumCircuit(key, work, phase, result)

# 후보 키 00, 01, 10, 11을 같은 진폭으로 준비
qc.h(key)

# 위상 킥백용 |-> 상태
qc.x(phase[0])
qc.h(phase[0])

qc.barrier()

# E_k(P) == C를 만족하는 키 표시
encryption_oracle(qc, key, work, phase)

qc.barrier()

# 표시된 키의 진폭 증폭
diffuser(qc, key)

qc.barrier()

# 키 레지스터만 측정
qc.measure(key, result)


# ---------------------------------------------------------
# 시뮬레이션
# ---------------------------------------------------------
sampler = StatevectorSampler(seed=42)
job = sampler.run([qc], shots=1024)
pub_result = job.result()[0]

counts = pub_result.data.result.get_counts()

print(qc.draw())
print("측정 결과:", counts)
print("예상 키:", format(
    int("01", 2) ^ int("10", 2),
    "02b"
))