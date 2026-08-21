"""N=15 쇼어 차수 찾기를 직관적으로 확인하는 실행형 테스트.

This is an educational, N=15-specific circuit.  It demonstrates the quantum
order-finding part of Shor's algorithm for a=2; it is not a general-purpose
factorization implementation.
"""

from fractions import Fraction
from math import gcd

import numpy as np
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit.circuit.library import QFTGate
from qiskit.primitives import StatevectorSampler
from qiskit.quantum_info import Statevector


N = 15
A = 2


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def m2mod15():
    """Return the N=15-specific gate |x> -> |2x mod 15>."""
    circuit = QuantumCircuit(4, name="M2")
    circuit.swap(2, 3)
    circuit.swap(1, 2)
    circuit.swap(0, 1)
    return circuit


def m4mod15():
    """Return the N=15-specific gate |x> -> |4x mod 15>."""
    circuit = QuantumCircuit(4, name="M4")
    circuit.swap(1, 3)
    circuit.swap(0, 2)
    return circuit


def gate_output(gate, x):
    """Run a 4-qubit permutation gate on basis state |x> and return y."""
    state_in = Statevector.from_int(x, dims=2**4)
    state_out = state_in.evolve(gate)
    return int(np.argmax(state_out.probabilities()))


def test_modular_gates():
    """Visually compare every SWAP-gate output with classical arithmetic."""
    banner("TEST 1 - SWAP 회로가 정말 2x mod 15와 4x mod 15를 계산하는가?")
    print("M2: SWAP(2,3) -> SWAP(1,2) -> SWAP(0,1)")
    print("M4: SWAP(1,3) -> SWAP(0,2)\n")
    print(" x | M2 circuit | 2x mod 15 | M4 circuit | 4x mod 15")
    print("---+------------+-----------+------------+----------")

    all_passed = True
    for x in range(1, N):
        m2_actual = gate_output(m2mod15(), x)
        m4_actual = gate_output(m4mod15(), x)
        m2_expected = (2 * x) % N
        m4_expected = (4 * x) % N
        row_ok = m2_actual == m2_expected and m4_actual == m4_expected
        all_passed &= row_ok
        mark = "PASS" if row_ok else "FAIL"
        print(
            f"{x:2d} | {m2_actual:10d} | {m2_expected:9d} |"
            f" {m4_actual:10d} | {m4_expected:8d}   {mark}"
        )

    assert all_passed, "모듈러 곱셈 게이트 테스트 실패"
    print("\n[PASS] x=1,...,14에서 양자 회로와 고전 계산이 모두 일치합니다.")
    print("참고: 가역성을 위해 사용하지 않는 |15> 상태는 |15>로 유지됩니다.")


def show_order_orbit():
    """Show why the order of 2 modulo 15 is four without any quantum jargon."""
    banner("TEST 2 - 우리가 찾으려는 주기(차수)는 무엇인가?")

    x = 1
    orbit = [x]
    while True:
        x = (A * x) % N
        orbit.append(x)
        if x == 1:
            break

    print("1에서 시작해 2를 곱하고 매번 15로 나눈 나머지를 취합니다:")
    print("  " + " -> ".join(map(str, orbit)))
    order = len(orbit) - 1
    print(f"{order}번 만에 다시 1이 되므로 차수는 r={order}입니다.")
    assert order == 4
    print("[PASS] 고전 계산으로 확인한 기준 차수는 r=4입니다.")


def apply_controlled_m2(circuit, control, target):
    """Apply controlled-M2 using the same SWAP mapping as m2mod15()."""
    circuit.cswap(control, target[2], target[3])
    circuit.cswap(control, target[1], target[2])
    circuit.cswap(control, target[0], target[1])


def apply_controlled_m4(circuit, control, target):
    """Apply controlled-M4 using the same SWAP mapping as m4mod15()."""
    circuit.cswap(control, target[1], target[3])
    circuit.cswap(control, target[0], target[2])


def build_phase_estimation_circuit():
    """Build two-bit phase estimation for U|x> = |2x mod 15>."""
    control = QuantumRegister(2, "control")
    target = QuantumRegister(4, "target")
    measured = ClassicalRegister(2, "phase")
    circuit = QuantumCircuit(control, target, measured)

    # |target> = |0001> = |1>.  Qiskit displays bits as q3 q2 q1 q0.
    circuit.x(target[0])

    # Prepare four equally weighted control states: 00, 01, 10, 11.
    circuit.h(control)
    circuit.barrier()

    # control[0] selects U^(2^0)=M2; control[1] selects U^(2^1)=M4.
    apply_controlled_m2(circuit, control[0], target)
    apply_controlled_m4(circuit, control[1], target)
    circuit.barrier()

    # Convert phase information into ordinary 2-bit measurement probabilities.
    circuit.append(QFTGate(2).inverse(), list(control))
    circuit.measure(control, measured)
    return circuit


def classify_measurement(bits):
    """Convert one measured phase into an order candidate and factors."""
    phase = int(bits, 2) / 4
    order = Fraction(phase).limit_denominator(N).denominator

    if bits == "00":
        return phase, order, None, "위상 0: 차수 정보가 없어 재시도"
    if order % 2 != 0:
        return phase, order, None, "홀수 r: 탈락"
    if pow(A, order, N) != 1:
        return phase, order, None, f"2^{order} mod 15 != 1: 후보 탈락"

    p = gcd(pow(A, order // 2) - 1, N)
    q = gcd(pow(A, order // 2) + 1, N)
    factors = tuple(sorted((p, q)))
    if p in (1, N) or q in (1, N):
        return phase, order, None, "자명한 인수: 탈락"
    return phase, order, factors, "SUCCESS"


def run_quantum_test(shots=2048):
    """Sample phase estimation and explain every possible output."""
    banner("TEST 3 - 2비트 양자 위상 추정")
    circuit = build_phase_estimation_circuit()

    sampler = StatevectorSampler(seed=42)
    result = sampler.run([circuit], shots=shots).result()[0]
    counts = result.data.phase.get_counts()

    print("측정 분포(이상적 시뮬레이터):")
    for bits in ("00", "01", "10", "11"):
        count = counts.get(bits, 0)
        print(f"  {bits}: {count:4d}/{shots} = {count / shots:6.2%}")

    print("\n각 측정 비트열의 의미:")
    successful_factors = set()
    for bits in ("00", "01", "10", "11"):
        phase, order, factors, reason = classify_measurement(bits)
        if factors:
            successful_factors.add(factors)
        print(
            f"  bits={bits} -> phase={phase:.2f} -> r candidate={order}"
            f" -> {reason}"
            + (f" -> factors={factors}" if factors else "")
        )

    # In this exact example all four phases should appear at roughly 25%.
    assert set(counts) == {"00", "01", "10", "11"}
    assert (3, 5) in successful_factors
    print("\n[PASS] 01과 11에서 r=4를 얻어 인수 (3, 5)를 찾았습니다.")

    print("\n전체 회로(터미널 폭에 맞춰 접어서 표시):")
    print(circuit.draw(output="text", fold=120))


def main():
    print("교육용 쇼어 테스트: a=2를 사용해 N=15 인수분해")
    print("핵심: 양자 회로는 차수 r을 찾고, 고전 후처리는 인수를 구합니다.")
    test_modular_gates()
    show_order_orbit()
    run_quantum_test()


if __name__ == "__main__":
    main()
