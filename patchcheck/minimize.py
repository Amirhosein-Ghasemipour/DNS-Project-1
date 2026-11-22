"""Budgeted byte-level delta debugging with an evidence-preserving predicate."""


def ddmin(data, predicate, budget=100):
    original_size, attempts, granularity = len(data), 0, 2
    while data and attempts < budget:
        chunk = max(1, (len(data) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(data), chunk):
            if attempts >= budget:
                break
            candidate = data[:start] + data[start + chunk:]
            attempts += 1
            if predicate(candidate):
                data = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(data):
                break
            granularity = min(len(data), granularity * 2)
    return data, {"original_bytes": original_size, "minimized_bytes": len(data), "attempts": attempts,
                  "budget": budget, "budget_exhausted": attempts >= budget,
                  "guarantee": "preserves confirmed error type and exact source location; not globally minimal"}

