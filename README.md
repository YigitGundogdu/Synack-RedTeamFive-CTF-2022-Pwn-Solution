# Synack-RedTeamFive-CTF-2022-Pwn-challenge-Solution
This write-up was added for the [JohnyBGoode] challenge. Firstly we need to pass the lyrics part. When a program is executed, I receive options and parse them, then I send the indexes of the correct  options.  After that, I used the ROP technique to leak the "puts" address and specified the libc address. In this way, we get the shell.
