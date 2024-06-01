#!/usr/bin/env python3

from typing import List
from pwn import process, context

context.log_level = "error"

cases_to_run = ["1", "2", "3", "4", "5", "6", "7"]

TIMEOUT_SECONDS = 0.01


def wrap_recvrepeat(r):
    if r.poll() is not None:
        return b""
    return r.recvrepeat(TIMEOUT_SECONDS)


def recvrepeats(r):
    output = wrap_recvrepeat(r)
    while output == b"":
        if r.poll() is not None:
            break
        output = wrap_recvrepeat(r)

    ret = b""

    while output != b"":
        ret += output
        output = wrap_recvrepeat(r)

    return ret


def execute_process(
    case: str, command: List[str], stdin: List[str]
) -> tuple[int, bytes]:
    """Returns the exit code and output of the process (including stdin and stderr)"""
    print(f"Running case {case} with command: {command}")
    try:
        r = process(command, shell=False)
        output = b""
        for line in stdin:
            ret = recvrepeats(r)
            output += ret
            output += line.encode("utf-8")
            if r.poll() is None:  # Only send if the process is still running
                r.send(line.encode("utf-8"))
        output += recvrepeats(r)
        r.close()

    except Exception as e:
        print(f"Error: {e}")
        return 1, b""

    return 0, output


if __name__ == "__main__":
    # Clean up the diff file
    with open("diff.txt", "w") as f:
        f.write("")

    for case in cases_to_run:

        with open(f"{case}.in", "r") as f:
            lines = f.readlines()
            run_command: List[str] = lines[0].split()
            input = lines[1:]

        _, output = execute_process(case, run_command, input)

        # Remove the last prompt
        if output.endswith(b"(sdb) "):
            output = output[:-6]

        # Remove null bytes
        output = output.replace(b"\x00", b"")

        # Write the output to a file
        with open(f"{case}.out", "wb") as f:
            f.write(output)

        diff_command = f"diff -w -B -u {case}.out {case}.ans"
        diff_process = process(diff_command, shell=True)
        diff_output = diff_process.recvall()
        diff_process.close()

        diff_lines = diff_output.decode("utf-8").split("\n")
        diff_lines = [
            line for line in diff_lines if line.startswith("-") or line.startswith("+")
        ]
        diff_lines = [line for line in diff_lines if not line.startswith("---")]
        diff_lines = [line for line in diff_lines if not line.startswith("+++")]

        i = 0
        while True:
            if i + 1 >= len(diff_lines):
                break

            if "-$rbp" in diff_lines[i] and "+$rbp" in diff_lines[i + 1]:
                output_line = diff_lines.pop(i)[1:].split()
                expected_line = diff_lines.pop(i)[1:].split()

                if len(output_line) != 6:
                    diff_lines.append(f"error")
                    break

                output_rbp = int(output_line[1], 16)
                output_rsp = int(output_line[3], 16)
                output_r8 = int(output_line[5], 16)
                expected_rbp = int(expected_line[1], 16)
                expected_rsp = int(expected_line[3], 16)
                expected_r8 = int(expected_line[5], 16)

                if (
                    output_rbp - output_rsp != expected_rbp - expected_rsp
                    or output_r8 != expected_r8
                ):
                    diff_lines.append(f"error")
                    break

                continue

            i += 1

        # Print the diff output if there is a difference
        print(f"Case {case}: {'PASS' if len(diff_lines) == 0 else 'FAIL'}", end="\n\n")

        # Print the diff output to `diff.txt`
        if len(diff_lines) > 0:
            with open("diff.txt", "a") as f:
                f.write(diff_output.decode("utf-8"))
                f.write("\n\n")
