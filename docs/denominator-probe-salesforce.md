# Phase B Execution Guide — Salesforce

**Repo location:** `docs/denominator-probe-salesforce.md`
**Companion to:** `docs/denominator-probe.md` (the protocol)
**Time:** 2–3 hours, all in a browser. No local tooling, no cost.

---

## 0. What you are testing

One question decides whether Salesforce supports a class C1 denominator:

> Can you establish the true population of agent actions in a time window, independently of the vendor, and separate agent-originated actions from human-originated ones?

Phase A said probably yes, with one threat: the **"Set Audit Fields upon Record Creation"** permission lets `CreatedById` be written arbitrarily at insert. If that override leaves no trace, the isolation attribute is forgeable and the class collapses.

There is a second question Phase A did not ask, and it is the one that decides the outcome:

> **Is the permission state itself queryable through the API?**

If yes, the disqualifier becomes a *monitorable condition* — qualification checks it, post-market monitoring re-checks it — and Salesforce is C1 with a stated caveat. If no, the pessimistic reading stands and it drops to C3 or below.

Everything below serves those two questions.

---

## 1. Create the org (10 min)

1. Go to `developer.salesforce.com/signup`
2. Fill the form. Use a real email — you must verify it.
3. Pick any username in the form `you@probe.local` — it does not need to be a real address, but note it exactly.
4. Verify by email, set a password.

You now have a permanent free org. Nothing here expires.

---

## 2. Create the second user (10 min)

You need two distinguishable identities: one standing in for the agent's integration user, one for a human operator. You are already the human; create the agent.

1. Click the **gear icon** (top right) → **Setup**
2. In the Quick Find box, type `Users` → click **Users**
3. Click **New User**
4. Fill in: First Name `Agent`, Last Name `Integration`, Alias `agtin`, Email your real email, Username something like `agent@probe.local`
5. **User License:** Salesforce. **Profile:** System Administrator
6. Uncheck "Generate new password and notify user immediately" if you want to set it yourself, otherwise check your email
7. Save

**Record both User Ids.** In Setup → Users, click each user; the Id is the 18-character string in the browser URL after `/Users/`. It starts with `005`.

Write them down as `AGENT_ID` and `HUMAN_ID`. Every query below needs them.

---

## 3. Open the Developer Console

This is where all the probing happens. Gear icon → **Developer Console** (it opens a new window).

Two tools inside it:

- **Query Editor** — the tab at the bottom. Type SOQL, press Execute. This is for reading.
- **Execute Anonymous** — menu: **Debug → Open Execute Anonymous Window**. This runs Apex code. This is for writing.

---

## 4. Create the records (30 min elapsed, 5 min of work)

Log in as the **agent** user in a separate browser (or private window), open its Developer Console, and run this in Execute Anonymous:

```apex
List<Case> cases = new List<Case>();
for (Integer i = 0; i < 10; i++) {
    cases.add(new Case(Subject = 'AGENT-' + i, Status = 'New', Origin = 'Web'));
}
insert cases;
System.debug('created ' + cases.size());
```

Then, as **yourself** (the human), in your own Developer Console:

```apex
List<Case> cases = new List<Case>();
for (Integer i = 0; i < 10; i++) {
    cases.add(new Case(Subject = 'HUMAN-' + i, Status = 'New', Origin = 'Phone'));
}
insert cases;
```

**Note the current UTC time** before and after. You need the window bounds.

Wait 30 minutes before the next step. That wait is itself a measurement — see step 6.

---

## 5. Enumeration test

In Query Editor, replacing the timestamps with your window:

```sql
SELECT Id, Subject, CreatedById, CreatedDate, LastModifiedById, SystemModstamp
FROM Case
WHERE CreatedDate >= 2026-08-07T14:00:00Z
  AND CreatedDate <= 2026-08-07T15:00:00Z
ORDER BY CreatedDate ASC
```

**Record:** total row count (should be 20), whether the console reports more rows available, and whether it paginates.

**What you are checking:** does the API return the complete population for a bounded window, and does it *signal* when it has truncated rather than silently cutting off?

---

## 6. Isolation test — the one that matters most

```sql
SELECT Id, Subject, CreatedById, CreatedDate
FROM Case
WHERE CreatedById = 'PASTE_AGENT_ID_HERE'
  AND CreatedDate >= 2026-08-07T14:00:00Z
  AND CreatedDate <= 2026-08-07T15:00:00Z
```

**Record:** does it return exactly the 10 agent Cases and nothing else?

**What you are checking:** CM-005 identity isolation. If this returns exactly 10, the population query and the isolation filter are the *same query* — which is what makes Salesforce stronger than Zendesk, where they live in two APIs that do not compose.

---

## 7. Settlement lag

Create one more Case, note the exact second, then re-run the step 5 query immediately, then every 30 seconds until it appears.

**Record:** seconds between creation and visibility in enumeration.

This becomes `settlement_lag_s` in the QualificationRecord. It determines how long after a window closes you may enumerate it.

---

## 8. THE OVERRIDE TEST — decisive

This is the test the whole probe exists for.

### 8a. Enable the org preference

1. Setup → Quick Find: `User Interface` → click **User Interface**
2. Find the checkbox for **"Enable 'Set Audit Fields upon Record Creation' and 'Update Records with Inactive Owners' User Permissions"**
3. Check it, Save

*(If you cannot find it, search Setup for `audit fields`. Salesforce moves settings between releases.)*

### 8b. Grant the permission

1. Setup → Quick Find: `Permission Sets` → **New**
2. Label: `Audit Field Override`, API name auto-fills. Save.
3. Click **System Permissions** → **Edit**
4. Check **"Set Audit Fields upon Record Creation"** → Save
5. Click **Manage Assignments** → **Add Assignment** → select your own user → Assign

**Note what you just did:** granting this required Setup access. An agent vendor integrating into an enterprise's Salesforce org cannot do this — the enterprise's admin must. That asymmetry is the reason this may be survivable.

### 8c. Create a record with a forged creator

In Execute Anonymous, **as yourself**:

```apex
Case c = new Case(Subject = 'OVERRIDE-TEST', Status = 'New', Origin = 'Web');
c.CreatedById = 'PASTE_AGENT_ID_HERE';
c.CreatedDate = DateTime.newInstanceGmt(2026, 8, 7, 14, 30, 0);
insert c;
System.debug('inserted ' + c.Id);
```

**Record:** did it succeed? Note the returned Id.

### 8d. THE DIFF

Retrieve one honest agent-created Case and the forged one, with every field:

```sql
SELECT FIELDS(ALL)
FROM Case
WHERE Subject IN ('AGENT-0', 'OVERRIDE-TEST')
LIMIT 200
```

**Copy the full raw output of both rows.** Do not summarise. Then compare them field by field.

**The question:** is there ANY field — including ones not in Salesforce's published documentation — that distinguishes the forged record from the honest one?

- **If yes** → the override is detectable per-record. Strong C1.
- **If no** → detection rests entirely on the Setup Audit Trail entry for the permission grant, which is org-level and time-bounded at 180 days.

Also check `SystemModstamp` and `LastModifiedById` on the forged record — Phase A flagged as undocumented whether those are also writable under this permission.

---

## 9. PERMISSION STATE — the question that decides the outcome

```sql
SELECT AssigneeId, Assignee.Name, PermissionSetId, PermissionSet.Name
FROM PermissionSetAssignment
WHERE PermissionSet.PermissionsCreateAuditFields = true
```

**If that errors on the field name**, find the right one:

```sql
SELECT Id, Name, Label FROM PermissionSet WHERE IsOwnedByProfile = false
```

then in Setup → Object Manager, or via the Developer Console's schema browser, look for the boolean field on `PermissionSet` corresponding to the audit-fields permission. Also check `Profile` — the permission can be granted at profile level too, and a query covering only permission sets would miss it.

**Record:** can you determine, purely from the API, whether a given user currently holds this permission?

- **Yes** → the disqualifier is a monitorable condition. Qualification checks it, monitoring re-checks it, and the attestation states it. **This is the finding that makes Salesforce C1.**
- **No** → you cannot prove at attestation time that the isolation attribute was trustworthy during the window, and the class caps lower.

---

## 10. Mutability

```apex
Case c = [SELECT Id FROM Case WHERE Subject = 'HUMAN-0' LIMIT 1];
delete c;
```

Then re-run the step 5 enumeration query.

**Record:** does the deleted Case still appear? Then try:

```sql
SELECT Id, Subject, IsDeleted FROM Case WHERE IsDeleted = true ALL ROWS
```

**What you are checking:** whether a record can leave the denominator without trace. Soft delete that remains queryable is fine; hard delete that vanishes is a downgrade condition.

---

## 11. What to write down

Fill this out and keep the raw API output alongside it. Per DP-002, paste raw responses — not summaries.

| Field | Your finding |
|---|---|
| Enumeration API and scoping parameters | |
| Total returned vs expected (20) | |
| Truncation signalled? | |
| Isolation: exactly 10 agent records? | |
| Isolation attribute | `CreatedById` |
| Attribute caller-settable? | |
| **Override leaves per-record trace?** | |
| **Permission state API-queryable?** | |
| Settlement lag (seconds) | |
| Authoritative timestamp | `CreatedDate` (server-set unless overridden) |
| Delete leaves trace? | |
| `SystemModstamp` writable under override? | |

---

## 12. Reading the result

**C1 (green)** — enumeration complete and signalled, isolation exact, and permission state API-queryable. Proceed: `record.create` on Salesforce becomes the MVP action family, and design-partner selection targets vendors whose agents act in Salesforce.

**C1 with caveat (amber-green)** — the above, but the override leaves no per-record trace *and* permission state is queryable. Workable: the attestation states the condition and monitoring watches it. Write the limitation into the qualification record honestly.

**C3 or below (amber)** — permission state not queryable. Coverage caps at `enforced`, never `reconciled`. Probe two more systems (ServiceNow and Jira are the next candidates on the system-of-record axis) before accepting it.

**Red** — isolation fails outright. Reconsider before more coverage-engine work.

---

## 13. Then, immediately

Run the Stripe test the same day. Two API keys, two refunds, one diff, twenty minutes. Phase A predicts C5 on the absence of any actor attribute, and a confirmed negative there is the cheapest strong evidence in the set — it either confirms the system-of-record versus transaction-processor split or overturns it.
