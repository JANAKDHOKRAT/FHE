#!/usr/bin/env python3
"""Qualify PINE training using separate OS processes and bounded local pipes.

This runner is explicitly NOT a malicious-evaluator-secure deployment. It uses
an independent plaintext-reference path for qualification. Collector keys never
leave the collector process. All processes here share an OS user: separate
operators/hosts and authenticated transport remain deployment obligations.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import time

MAGIC = b"PNEIPC01"
MAX_FRAME = 128 * 1024 * 1024
TIMEOUT = 180


def read_exact(stream, size):
    out = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(out) < size:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([stream], [], [], left)[0]:
            raise TimeoutError("role frame timed out")
        try:
            part = os.read(stream.fileno(), min(65536, size - len(out)))
        except BlockingIOError:
            continue
        if not part:
            raise RuntimeError("role closed its stream")
        out.extend(part)
    return bytes(out)


def receive(stream, kind, limit=MAX_FRAME):
    header = read_exact(stream, 17)
    if header[:8] != MAGIC or header[8] != kind:
        raise RuntimeError("wrong role frame")
    count = struct.unpack("<Q", header[9:])[0]
    if count > limit:
        raise RuntimeError("oversized role frame")
    return read_exact(stream, count)


def send(stream, kind, body):
    deadline = time.monotonic() + TIMEOUT
    for part in (MAGIC + bytes([kind]) + struct.pack("<Q", len(body)), body):
        remaining = memoryview(part)
        while remaining:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([], [stream], [], left)[1]:
                raise TimeoutError("role write timed out")
            try:
                sent = os.write(stream.fileno(), remaining[:65536])
            except BlockingIOError:
                continue
            if not sent:
                raise RuntimeError("role closed its stream")
            remaining = remaining[sent:]


def unframe(raw, kind, limit=MAX_FRAME):
    if len(raw) < 17 or raw[:8] != MAGIC or raw[8] != kind:
        raise RuntimeError("invalid completed role output")
    count = struct.unpack("<Q", raw[9:17])[0]
    if count > limit or count != len(raw) - 17:
        raise RuntimeError("invalid completed frame length")
    return raw[17:]


def private_file(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def checkpoint(path):
    raw = path.read_bytes()
    if len(raw) < 64 or raw[:8] != b"PINEFL01" or hashlib.sha256(raw[:-32]).digest() != raw[-32:]:
        raise RuntimeError("bad model checkpoint")
    round_id, features, classes = struct.unpack("<QQQ", raw[8:32])
    count = (features + 1) * classes
    if len(raw) != 64 + 8 * count:
        raise RuntimeError("model size mismatch")
    return round_id, struct.unpack("<" + "d" * count, raw[32:-32])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("digits_csv", type=Path)
    parser.add_argument("new_output", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--allow-unverified-evaluator", action="store_true")
    args = parser.parse_args()
    if not args.allow_unverified_evaluator:
        parser.error("cryptographic evaluator authentication is absent; qualification requires --allow-unverified-evaluator")
    if args.rounds < 1 or not 2 <= args.clients <= 64:
        parser.error("positive rounds and 2..64 clients required")
    binary = str(args.binary.resolve(strict=True))
    root = args.new_output.resolve()
    root.mkdir(mode=0o700)
    env = {k: os.environ[k] for k in ("PATH", "LD_LIBRARY_PATH", "OMP_NUM_THREADS") if k in os.environ}
    children = []
    records = []

    def start(role, *arguments, cwd=root):
        p = subprocess.Popen([binary, role, *map(str, arguments)], cwd=cwd, env=env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        # select() only promises some capacity. Nonblocking descriptors keep
        # a peer that stops reading from bypassing our write deadline.
        os.set_blocking(p.stdin.fileno(), False)
        os.set_blocking(p.stdout.fileno(), False)
        children.append(p)
        records.append({"role": role, "pid": p.pid})
        return p

    def call(role, *arguments, cwd=root):
        p = start(role, *arguments, cwd=cwd)
        out, err = p.communicate(timeout=TIMEOUT)
        if p.returncode:
            raise RuntimeError(f"{role} refused: {err.decode(errors='replace').strip()}")
        return out

    try:
        raw = args.digits_csv.read_bytes()
        local = [[] for _ in range(args.clients)]
        held_out = []
        count = 0
        for index, row in enumerate(csv.reader(raw.decode().splitlines())):
            values = list(map(int, row))
            if len(values) != 65 or any(not 0 <= x <= 16 for x in values[:64]) or not 0 <= values[64] <= 9:
                raise ValueError("invalid digits data")
            line = ",".join([*(str(x / 16.0) for x in values[:64]), str(values[64])])
            if index % 5 == 0:
                held_out.append(line)
            else:
                local[count % args.clients].append(line)
                count += 1
        if not held_out or any(not rows for rows in local):
            raise ValueError("empty client or test dataset")
        test = root / "test.csv"
        private_file(test, ("\n".join(held_out) + "\n").encode())
        clients = []
        for i, rows in enumerate(local):
            directory = root / f"client-{i}"
            directory.mkdir(mode=0o700)
            key = directory / "signing.key"
            identity = unframe(call("keygen", key, cwd=directory), 7, 32)
            if len(identity) != 32:
                raise RuntimeError("invalid client identity")
            data = directory / "data.csv"
            private_file(data, ("\n".join(rows) + "\n").encode())
            clients.append((identity, key, data, directory))
        clients.sort(key=lambda client: client[0])
        identities = root / "identities.bin"
        private_file(identities, b"".join(client[0] for client in clients))
        config = root / "job.json"
        job = {"application": list(hashlib.sha256(raw).digest()), "min_accepted": args.clients,
               "params": {"dimension": 650, "l2_norm_bound": 32768, "num_frac_bits": 15,
                          "chunk_length": 4, "chunk_length_norm_equality": 4,
                          "num_proofs": 7, "num_proofs_norm_equality": 4},
               "training": {"local_epochs": 5, "local_learning_rate": 0.5, "server_learning_rate": 1.0}}
        private_file(config, json.dumps(job).encode())
        model = root / "model-0.bin"
        call("init-model", 64, 10, model)
        with (root / "rounds.jsonl").open("x") as evidence:
            for round_id in range(args.rounds):
                started = time.monotonic()
                first_record = len(records)
                task = root / f"task-{round_id}.bin"
                call("task", model, config, identities, task)
                collector_dir = root / f"collector-{round_id}"
                evaluator_dir = root / f"evaluator-{round_id}"
                collector_dir.mkdir(mode=0o700)
                evaluator_dir.mkdir(mode=0o700)
                collector = start("collector", task, collector_dir, args.clients, "--allow-unverified-evaluator", cwd=collector_dir)
                public_key = receive(collector.stdout, 1, 4 * 1024 * 1024)
                pk_file = root / f"public-key-{round_id}.bin"
                private_file(pk_file, public_key)
                evaluator = start("evaluator", task, evaluator_dir, pk_file, args.clients, cwd=evaluator_dir)
                reference = [0] * 650
                report_bytes = 0
                for identity, key, data, directory in clients:
                    # Reference oracle outputs are NEVER forwarded to evaluator/collector.
                    q = json.loads(call("reference", task, model, config, data, cwd=directory))
                    if len(q) != 650 or any(type(x) is not int for x in q):
                        raise RuntimeError("invalid quantized reference")
                    reference = [a + b for a, b in zip(reference, q)]
                    report = unframe(call("client", task, model, config, data, key, pk_file, cwd=directory), 2)
                    report_bytes += len(report)
                    send(evaluator.stdin, 2, report)
                check = receive(evaluator.stdout, 3)
                send(collector.stdin, 3, check)
                verdict = receive(collector.stdout, 4, (args.clients + 7) // 8)
                send(evaluator.stdin, 4, verdict)
                aggregate = receive(evaluator.stdout, 5)
                send(collector.stdin, 5, aggregate)
                released = receive(collector.stdout, 6, 40 + 650 * 8)
                if len(released) != 40 + 650 * 8 or released[:32] != hashlib.sha256(task.read_bytes()).digest():
                    raise RuntimeError("wrong release task/size")
                accepted = struct.unpack("<Q", released[32:40])[0]
                summed = struct.unpack("<650d", released[40:])
                if accepted != args.clients or summed != tuple(x / 32768.0 for x in reference):
                    raise RuntimeError("encrypted result differs from integer reference")
                for p in (evaluator, collector):
                    p.stdin.close()
                    if p.wait(timeout=TIMEOUT) != 0:
                        raise RuntimeError("server process failed")
                    if p.stdout.read():
                        raise RuntimeError("server emitted unexpected extra data")
                release_file = root / f"release-{round_id}.bin"
                private_file(release_file, MAGIC + bytes([6]) + struct.pack("<Q", len(released)) + released)
                next_model = root / f"model-{round_id+1}.bin"
                status = json.loads(call("update", task, model, config, release_file, next_model, test))
                old_round, old_weights = checkpoint(model)
                next_round, weights = checkpoint(next_model)
                expected = tuple(w + (q / 32768.0) / args.clients for w, q in zip(old_weights, reference))
                if weights != expected or old_round != round_id or next_round != round_id + 1:
                    raise RuntimeError("model differs from independent plaintext update")
                record = {"round": round_id, "accepted": accepted, "parameters": 650,
                          "separate_processes": True, "integer_sum_exact": True, "model_exact": True,
                          "test_accuracy": status["accuracy"], "report_bytes": report_bytes,
                          "check_bytes": len(check), "aggregate_bytes": len(aggregate),
                          "seconds": time.monotonic() - started, "roles": records[first_record:]}
                evidence.write(json.dumps(record) + "\n")
                evidence.flush()
                os.fsync(evidence.fileno())
                print(json.dumps(record), flush=True)
                model = next_model
        private_file(root / "processes.json", json.dumps(records, indent=2).encode())
    finally:
        for p in children:
            if p.poll() is None:
                p.kill()
            p.wait()
            for pipe in (p.stdin, p.stdout, p.stderr):
                if pipe is not None:
                    pipe.close()


if __name__ == "__main__":
    main()
