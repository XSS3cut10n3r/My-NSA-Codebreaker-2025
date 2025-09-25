# Task 1 - Getting Started (Forensics)

> You arrive on site and immediately get to work. The DAFIN-SOC team quickly briefs you on the situation. They have noticed numerous anomalous behaviors, such as: tools randomly failing tests and anti-virus flagging on seemingly clean workstations. They have narrowed in on one machine they would like NSA to thoroughly evaluate.

> They have provided a zipped EXT2 image from this development machine. Help DAFIN-SOC perform a forensic analysis on this - looking for any suspicious artifacts.

---

## Downloads

- **zipped EXT2 image:** `image.ext2.zip`

---

## Task

- **Provide the SHA-1 hash of the suspicious artifact.**

---

## Writeup

I started by mounting the EXT2 image in read-only mode so I could safely explore its contents.  
*(insert screenshot here)*  

The first place I looked was the root user’s `.bash_history`, since that often tells the story of what happened on the system. The history revealed a **pattern**: lots of local network probing (using `curl`, `wget`, `nc`, `netstat`, etc.), checks against DNS, and even repeated calls to `http://localhost/app/test`. Mixed in were commands to mount `/dev/sdb1` to `/mnt/usb` and edits to the crontab. In other words, whoever was on this box was hammering on a local web service, staging files via USB, and attempting persistence through cron.  
*(insert screenshot here)*  

With `/app/test` as a pivot point, I ran a recursive search through the mounted filesystem. This led me to an odd discovery:  

/etc/terminfo/s/nsuvzemaow


Inside this file was a reference to `/app/www`. That was a red flag — terminfo directories are supposed to store compiled terminal capability files, not random application paths. The filename itself looked auto-generated or intentionally obfuscated, which made it even more suspicious.  
*(insert screenshot here)*  

To confirm, I calculated the SHA-1 hash of the file:  

0068e0c3cba711e775fa374b201d5d04ffcef96c


*(insert screenshot here)*  

In the end, I flagged `/etc/terminfo/s/nsuvzemaow` as the suspicious artifact because:  

1. **Wrong place, wrong content** — it lived in a system directory but pointed to an application path.  
2. **Suspicious naming** — the file name looked random, not like a legitimate terminfo entry.  
3. **Correlation with activity** — its `/app` reference matched the probing seen in `.bash_history`.  

That combination made it stand out as the planted or compromised artifact. I submitted its SHA-1 hash as the solution.
