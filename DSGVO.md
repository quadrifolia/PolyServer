# DSGVO/GDPR Compliance Guide

This document provides guidance on DSGVO (Datenschutz-Grundverordnung) / GDPR (General Data Protection Regulation) compliance for applications deployed on the PolyServer foundation. It outlines procedures to follow in case of data breaches or other incidents involving personal data, regardless of the specific application type.

## Table of Contents

- [Data Protection Officer Information](#data-protection-officer-information)
- [Personal Data in Applications](#personal-data-in-applications)
- [Data Breach Response Procedure](#data-breach-response-procedure)
  - [Identification and Containment](#identification-and-containment)
  - [Assessment and Documentation](#assessment-and-documentation)
  - [Notification Requirements](#notification-requirements)
  - [Follow-up Actions](#follow-up-actions)
- [Regulatory Contacts](#regulatory-contacts)
- [Documentation Templates](#documentation-templates)
  - [Internal Data Breach Report](#internal-data-breach-report)
  - [Data Subject Notification](#data-subject-notification)
  - [Authority Notification](#authority-notification)
- [DSGVO/GDPR Tools and Resources](#dsgvogdpr-tools-and-resources)

## Data Protection Officer Information

[Complete this section with your organization's specific information]

**Data Protection Officer (DPO):**
- Name: [DPO Name]
- Email: [DPO Email]
- Phone: [DPO Phone]

**Alternate Contact:**
- Name: [Alternate Contact Name]
- Email: [Alternate Contact Email]
- Phone: [Alternate Contact Phone]

## Personal Data in Applications

Applications deployed on PolyServer may contain or provide access to various types of personal data. Document the categories of personal data accessible through your applications:

| Data Category | Description | Access Level | Retention Period |
|---------------|-------------|--------------|------------------|
| [Customer Data] | [Describe data] | [Who has access] | [How long kept] |
| [Employee Data] | [Describe data] | [Who has access] | [How long kept] |
| [Analytics Data] | [Describe data] | [Who has access] | [How long kept] |
| [User Data] | [Describe data] | [Who has access] | [How long kept] |
| [Session Data] | [Describe data] | [Who has access] | [How long kept] |
| [Application-Specific Data] | [Describe data] | [Who has access] | [How long kept] |

## Data Breach Response Procedure

### Identification and Containment

1. **Immediate Response** (first 24 hours):
   - The person who discovers or suspects a data breach must immediately notify the Security Team and DPO
   - Contact methods:
     - Email: [security@your-organization.com]
     - Phone: [Emergency security phone number]
     - Incident response platform: [Link to platform if available]

2. **Initial Containment** (first 24-48 hours):
   - Isolate affected systems to prevent further data exposure
   - Preserve evidence for forensic investigation
   - Use the [incident response tools](/README.md#incident-response-tools) documented in the main README
   - Document all actions taken using the [Internal Data Breach Report](#internal-data-breach-report) template

3. **Activate Response Team**:
   - Security Officer
   - Data Protection Officer
   - IT Administrator
   - Legal Counsel
   - Communications Representative

### Assessment and Documentation

1. **Breach Assessment** (within 48-72 hours):
   - Determine what personal data was affected
   - Identify the number of data subjects affected
   - Assess potential consequences for affected individuals
   - Determine if the breach is ongoing or contained
   - Evaluate if encryption or other measures protected the data

2. **Documentation Requirements**:
   - Timeline of the breach (detection, response, containment)
   - Nature of the breach (what happened)
   - Categories of data affected
   - Number of individuals affected
   - Likely consequences
   - Measures taken to address the breach
   - Use the structured documentation format in the [templates section](#documentation-templates)

### Notification Requirements

#### To Supervisory Authority

1. **When to Notify**:
   - Within 72 hours of becoming aware of a breach
   - Unless the breach is unlikely to result in a risk to individuals' rights and freedoms
   
2. **Authority to Notify**:
   - For Bremen, Germany: Die Landesbeauftragte für Datenschutz und Informationsfreiheit Bremen
   - For other locations, see [Regulatory Contacts](#regulatory-contacts)

3. **Information to Include**:
   - Description of the breach
   - Name and contact details of DPO
   - Likely consequences
   - Measures taken or proposed
   - Categories and approximate number of data subjects concerned
   - Categories and approximate number of records concerned

#### To Affected Individuals

1. **When to Notify**:
   - Without undue delay
   - When breach is likely to result in a high risk to rights and freedoms

2. **How to Notify**:
   - Direct communication (email, letter, phone)
   - Public communication if direct contact is disproportionate

3. **Information to Include**:
   - Clear, plain language description of the breach
   - Name and contact details of DPO
   - Likely consequences
   - Measures taken or proposed
   - Specific recommendations for individuals to protect themselves

### Follow-up Actions

1. **Remediation**:
   - Implement technical fixes to address vulnerabilities
   - Update security protocols if necessary
   - Consider implementing additional security measures

2. **Review and Lessons Learned**:
   - Conduct post-incident review within 2 weeks
   - Document lessons learned
   - Update security procedures based on findings
   - Schedule follow-up assessment after 1 month

3. **Documentation Retention**:
   - All breach-related documentation must be retained for at least 5 years

## Regulatory Contacts

### Germany

**Federal Authority:**
- Bundesbeauftragte für den Datenschutz und die Informationsfreiheit (BfDI)
- Phone: +49 (0)228 997799 0
- Email: poststelle@bfdi.bund.de
- Website: https://www.bfdi.bund.de/

**Regional Authorities by Federal State:**

**Baden-Württemberg:**
- Der Landesbeauftragte für den Datenschutz und die Informationsfreiheit Baden-Württemberg
- Phone: +49 711 615541-0
- Email: poststelle@lfdi.bwl.de
- Website: https://www.baden-wuerttemberg.datenschutz.de
- Address: Königstraße 10a, 70173 Stuttgart

**Bayern (Bavaria):**
- Der Bayerische Landesbeauftragte für den Datenschutz
- Phone: +49 89 212672-0
- Email: poststelle@datenschutz-bayern.de
- Website: https://www.datenschutz-bayern.de
- Address: Wagmüllerstraße 18, 80538 München

**Berlin:**
- Berliner Beauftragte für Datenschutz und Informationsfreiheit
- Phone: +49 30 13889-0
- Email: mailbox@datenschutz-berlin.de
- Website: https://www.datenschutz-berlin.de
- Address: Friedrichstraße 219, 10969 Berlin

**Brandenburg:**
- Die Landesbeauftragte für den Datenschutz und für das Recht auf Akteneinsicht Brandenburg
- Phone: +49 331 974-1450
- Email: poststelle@lda.brandenburg.de
- Website: https://www.lda.brandenburg.de
- Address: Stahnsdorfer Damm 77, 14532 Kleinmachnow

**Bremen:**
- Die Landesbeauftragte für Datenschutz und Informationsfreiheit Bremen
- Phone: +49 421 361-2010
- Email: office@datenschutz.bremen.de
- Website: https://www.datenschutz.bremen.de
- Address: Arndtstraße 1, 27570 Bremerhaven

**Hamburg:**
- Der Hamburgische Beauftragte für Datenschutz und Informationsfreiheit
- Phone: +49 40 428 54-4040
- Email: mailbox@datenschutz.hamburg.de
- Website: https://datenschutz-hamburg.de
- Address: Klosterwall 6, 20095 Hamburg

**Hessen:**
- Der Hessische Beauftragte für Datenschutz und Informationsfreiheit
- Phone: +49 611 1408-0
- Email: poststelle@datenschutz.hessen.de
- Website: https://datenschutz.hessen.de
- Address: Poststraße 1, 65189 Wiesbaden

**Mecklenburg-Vorpommern:**
- Der Landesbeauftragte für Datenschutz und Informationsfreiheit Mecklenburg-Vorpommern
- Phone: +49 385 59494-0
- Email: info@datenschutz-mv.de
- Website: https://www.datenschutz-mv.de
- Address: Werderstraße 74a, 19055 Schwerin

**Niedersachsen (Lower Saxony):**
- Die Landesbeauftragte für den Datenschutz Niedersachsen
- Phone: +49 511 120-4500
- Email: poststelle@lfd.niedersachsen.de
- Website: https://www.lfd.niedersachsen.de
- Address: Prinzenstraße 5, 30159 Hannover

**Nordrhein-Westfalen (North Rhine-Westphalia):**
- Landesbeauftragte für Datenschutz und Informationsfreiheit Nordrhein-Westfalen
- Phone: +49 211 38424-0
- Email: poststelle@ldi.nrw.de
- Website: https://www.ldi.nrw.de
- Address: Kavalleriestraße 2-4, 40213 Düsseldorf

**Rheinland-Pfalz (Rhineland-Palatinate):**
- Der Landesbeauftragte für den Datenschutz und die Informationsfreiheit Rheinland-Pfalz
- Phone: +49 6131 208-2449
- Email: poststelle@datenschutz.rlp.de
- Website: https://www.datenschutz.rlp.de
- Address: Hintere Bleiche 34, 55116 Mainz

**Saarland:**
- Unabhängiges Datenschutzzentrum Saarland
- Phone: +49 681 94781-0
- Email: poststelle@datenschutz.saarland.de
- Website: https://datenschutz.saarland.de
- Address: Fritz-Dobisch-Straße 12, 66111 Saarbrücken

**Sachsen (Saxony):**
- Der Sächsische Datenschutzbeauftragte
- Phone: +49 351 85471-0
- Email: saechsdsb@slt.sachsen.de
- Website: https://www.saechsdsb.de
- Address: Devrientstraße 5, 01067 Dresden

**Sachsen-Anhalt:**
- Landesbeauftragter für den Datenschutz Sachsen-Anhalt
- Phone: +49 391 81803-0
- Email: poststelle@lfd.sachsen-anhalt.de
- Website: https://datenschutz.sachsen-anhalt.de
- Address: Leiterstraße 9, 39104 Magdeburg

**Schleswig-Holstein:**
- Unabhängiges Landeszentrum für Datenschutz Schleswig-Holstein
- Phone: +49 431 988-1200
- Email: mail@datenschutzzentrum.de
- Website: https://www.datenschutzzentrum.de
- Address: Holstenstraße 98, 24103 Kiel

**Thüringen (Thuringia):**
- Der Thüringer Landesbeauftragte für den Datenschutz und die Informationsfreiheit
- Phone: +49 361 57711-2900
- Email: poststelle@datenschutz.thueringen.de
- Website: https://www.tlfdi.de
- Address: Häßlerstraße 8, 99096 Erfurt

### Other EU Member States

For operations in other EU member states, consult the European Data Protection Board's list of supervisory authorities:
- [EDPB Members](https://edpb.europa.eu/about-edpb/about-edpb/members_en)

## Documentation Templates

### Internal Data Breach Report

```
INTERNAL DATA BREACH REPORT
===========================

INCIDENT DETAILS
---------------
Date and time of discovery: [YYYY-MM-DD HH:MM]
Date and time of breach (if known): [YYYY-MM-DD HH:MM]
Discovered by: [Name/Role]
Breach reference number: [ORG-YEAR-NUMBER]

BREACH DETAILS
-------------
Description of breach:
[Detailed description]

Systems affected:
[List affected systems]

Personal data affected:
[Types of personal data]

Categories of data subjects:
[Types of individuals affected]

Approximate number of data subjects affected:
[Number or range]

Approximate number of records affected:
[Number or range]

IMPACT ASSESSMENT
---------------
Potential consequences for data subjects:
[Description of potential harm]

Risk level:
[ ] Low - unlikely to result in risk to individuals
[ ] Medium - may result in risk to individuals
[ ] High - likely to result in high risk to individuals

Reasoning for risk assessment:
[Explanation of risk classification]

RESPONSE ACTIONS
--------------
Containment measures taken:
[Actions taken to limit the breach]

Evidence preserved:
[List of evidence collected]

Technical remediation:
[Technical steps taken to fix the issue]

NOTIFICATION DECISIONS
--------------------
Supervisory authority notification:
[ ] Required (medium/high risk) - Deadline: [Date/time - 72h after discovery]
[ ] Not required (low risk) - Justification: [Reasoning]

Data subject notification:
[ ] Required (high risk) - Deadline: [Date/time - without undue delay]
[ ] Not required (low/medium risk) - Justification: [Reasoning]

APPROVALS
--------
Report completed by: [Name, Role]
Date: [YYYY-MM-DD]

DPO review: [Name, Comments]
Date: [YYYY-MM-DD]

Legal review: [Name, Comments]
Date: [YYYY-MM-DD]
```

### Data Subject Notification

```
SUBJECT: IMPORTANT: Data Security Incident Notification

Dear [Data Subject],

We are writing to inform you about a data security incident that occurred on [date] 
which may have affected your personal data.

What happened:
[Clear description of the breach in plain language]

What information was involved:
[Types of personal data affected]

What this means for you:
[Potential consequences]

What we are doing:
[Actions taken to address the breach and protect data]

What you can do:
[Specific advice on how individuals can protect themselves]

Further information and contact details:
If you have any questions or concerns, please contact our Data Protection Officer:
- Name: [DPO Name]
- Email: [DPO Email]
- Phone: [DPO Phone]

We sincerely apologize for this incident and any concern it may cause you.

Yours sincerely,
[Name]
[Position]
[Organization]
```

### Authority Notification

```
DATA BREACH NOTIFICATION TO SUPERVISORY AUTHORITY
================================================

1. CONTROLLER DETAILS
--------------------
Organization name: [Organization name]
Address: [Full address]
Registration number: [If applicable]

2. CONTACT DETAILS
----------------
Primary contact: [Name, Position]
Phone: [Direct phone number]
Email: [Direct email]

Data Protection Officer:
Name: [DPO name]
Phone: [DPO phone]
Email: [DPO email]

3. BREACH DETAILS
---------------
Date and time of breach (if known): [YYYY-MM-DD HH:MM]
Date and time of discovery: [YYYY-MM-DD HH:MM]
Ongoing breach: [Yes/No]
If yes, current status: [Description of current situation]

Description of the breach:
[Detailed description including the type of breach (confidentiality, integrity, availability)]

Cause of the breach (if known):
[Description of how the breach occurred]

Systems and data involved:
[Description of affected systems, applications, or records]

4. DATA AND SUBJECTS AFFECTED
---------------------------
Categories of personal data affected:
[List all types of personal data]

Special categories of data affected:
[List any sensitive data as defined by GDPR Article 9]

Categories of data subjects:
[Types of individuals affected]

Approximate number of data subjects:
[Number or best estimate]

Approximate number of data records:
[Number or best estimate]

5. POTENTIAL CONSEQUENCES
----------------------
Likely consequences for data subjects:
[Description of potential harm to individuals]

Severity assessment:
[Low/Medium/High with justification]

6. MEASURES TAKEN
---------------
Containment measures already implemented:
[Actions taken to contain the breach]

Measures to address adverse effects:
[Actions taken to mitigate harm to individuals]

Technical and organizational measures in place before the breach:
[Security measures that were in place]

7. COMMUNICATION
--------------
Data subject notification:
[ ] Already notified on [date]
[ ] Will be notified by [date]
[ ] Not notifying - Justification: [Reasoning]

Content of notification to data subjects:
[Summary or attach copy]

Communication channel(s) used/to be used:
[Email/Letter/Phone/Public notice/etc.]

8. CROSS-BORDER ASPECTS
---------------------
Does the breach affect data subjects in other EU member states?
[ ] Yes - Member states affected: [List countries]
[ ] No

Has notification been made to other supervisory authorities?
[ ] Yes - Authorities notified: [List authorities]
[ ] No

9. ADDITIONAL INFORMATION
----------------------
[Any other relevant information]

10. ATTACHMENTS
-------------
[ ] Internal breach report
[ ] Technical investigation report
[ ] Data subject notification template
[ ] Other: [Specify]

Report completed by: [Name, Position]
Date: [YYYY-MM-DD]
```

## DSGVO/GDPR Tools and Resources

### Official Resources

- [European Data Protection Board (EDPB)](https://edpb.europa.eu/)
- [German Federal Commissioner for Data Protection (BfDI)](https://www.bfdi.bund.de/)
- [Bremen Data Protection Authority](https://www.datenschutz.bremen.de/)

### Risk Assessment Tools

- [DSGVO Compliance Checklist](https://gdpr.eu/checklist/)
- [Data Protection Impact Assessment Template](https://gdpr.eu/data-protection-impact-assessment-template/)

### Recommended Actions for Compliance

1. **Regular Data Mapping**
   - Document all personal data in Application
   - Review data access permissions quarterly
   - Validate data retention periods

2. **User Training**
   - Conduct regular DSGVO awareness training
   - Ensure all Application users understand data protection principles
   - Practice breach response procedures annually

3. **Technical Measures**
   - Maintain all security measures outlined in [README.md](/README.md#server-monitoring-and-security)
   - Implement data minimization in Application queries
   - Consider pseudonymization for analytics data
   - Ensure strong encryption for all personal data

4. **Documentation**
   - Maintain records of processing activities
   - Document data sharing agreements
   - Keep audit logs of data access
   - Regularly update privacy policies and notices