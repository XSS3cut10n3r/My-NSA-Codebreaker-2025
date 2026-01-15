# NSA Codebreaker Challenge 2025 Writeups

My writeups and solutions for the NSA Codebreaker Challenge.

## About Me + Reflection

I'm currently pursuing my Bachelor's degree at the SANS Institute with a focus on cybersecurity. My interest in the field grew from wanting to understand how networks and computer systems operate at a fundamental level, which naturally led me to security. 

This was my first NSA Codebreaker Challenge, and the sequential structure helped build skills progressively. Task 4 was definitely the highlight—it introduced me to real malware analysis techniques I hadn't worked with before. Bypassing the multi-layered anti-debug protections (ptrace detection, TracerPid checks, and the NULL pointer trap) taught me how malware authors actually defend their code. Using GDB catchpoints to monitor syscalls and extract the memfd payload was new territory for me, and reverse engineering the RC4 encryption scheme to decrypt the hidden file path felt like solving a puzzle where everything finally clicked.

The Android exploitation in Task 7 was also fascinating—chaining the path traversal vulnerability with dynamic class loading to achieve RCE required thinking through the entire execution flow. Testing it locally with an emulator and watching the reverse shell connect was incredibly satisfying. Task 6's Mattermost vulnerability was more subtle; realizing the `!nego` command only validated source channel membership, not destination, and then using SQL CTEs to map the exploitation path through overlapping users was a different kind of problem-solving.

Looking back, I definitely spent too much time initially trying to brute-force solutions instead of stepping back to understand the mechanisms. In Task 2, I could've identified the DNS poisoning faster if I'd filtered for anomalies systematically rather than manually inspecting traffic. The forensics and reverse engineering tasks also taught me the importance of documenting findings as I go - I had to backtrack several times because I didn't keep proper notes on what I'd already discovered. Overall, the challenge reinforced that cybersecurity requires methodical thinking and patience as much as technical skills.

## Tasks

| Task | Name | Category |
|:-----|:-----|:--------:|
| [Task 1](./task1.md) | Getting Started | Forensics |
| [Task 2](./task2.md) | The Hunt Continues | Network Forensics |
| [Task 3](./task3.md) | Digging Deeper | Reverse Engineering |
| [Task 4](./task4.md) | Unpacking Insight | Malware Analysis |
| [Task 5](./task5.md) | Putting It All Together | Cryptanalysis |
| [Task 6](./task6.md) | Crossing the Channel | Vulnerability Research |
| [Task 7](./task7.md) | Finale | Vulnerability Research, Exploitation |

## About the Challenge

The NSA Codebreaker Challenge provides students with a hands-on opportunity to develop their reverse-engineering and low-level code analysis skills while working on a realistic problem set centered around the NSA's mission.

The challenge consists of a series of tasks worth varying points based on difficulty. Tasks are strictly sequential and must be solved in order. Each task requires a range of skills including reverse engineering, network analysis, cryptography, binary analysis, and web application security.

## Scenario

This year's challenge involves assisting the NSA's Cyber Response Team in investigating suspicious activity detected by the Air Force's Security Operations Center. The scenario involves analyzing potential infiltration attempts by advanced foreign adversaries targeting military cyber operations.

## Disclaimer

The challenge content is a purely fictional scenario created by the NSA for educational purposes only. Any similarities to real persons, entities, or events is coincidental.

## Note

These writeups are published after the challenge period has ended and are intended for educational purposes.
