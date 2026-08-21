from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

qc = QuantumCircuit(1, 1)

qc.h(0)          # |0> -> (|0> + |1>) / sqrt(2)
qc.measure(0, 0)

sim = AerSimulator()
compiled = transpile(qc, sim)
result = sim.run(compiled, shots=1024).result()

print(qc.draw())
print(result.get_counts())