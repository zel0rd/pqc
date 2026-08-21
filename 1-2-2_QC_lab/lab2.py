from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

qc = QuantumCircuit(2, 2)

qc.h(0)          # 첫 번째 qubit 중첩
qc.cx(0, 1)      # 두 번째 qubit과 얽힘 생성

qc.measure([0, 1], [0, 1])

sim = AerSimulator()
compiled = transpile(qc, sim)
result = sim.run(compiled, shots=1024).result()

print(qc.draw())
print(result.get_counts())