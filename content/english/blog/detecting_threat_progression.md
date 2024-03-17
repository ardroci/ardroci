---
title: "Detecting Threat Progression"
meta_title: ""
description: ""
date: 2024-01-02
image: "images/detecting_threat_progression/unified_kill_chain.png"
categories: ["Security"]
author: "ardroci"
tags: ["Threat Detection", "Strategy", "Fundamental Principles"]
draft: false
---

## The Need for Evolution in Threat Detection

Cyber threats are not static; they evolve as threat actors adapt their strategies to bypass defenses. Conventional detection methods often focus on individual signals in isolation. This blog post proposes the concept of "Detection of an Evolving Threat" to address this limitation, allowing detection engineers to track threats as they advance through the unified kill chain.

## Understanding and Implementing Detection of an Evolving Threat

Detection of an Evolving Threat represents a paradigm shift in the way we approach threat identification. It is underpinned by fundamental principles, each contributing to a more effective threat detection strategy.

#### Kill Chain Progression: Navigating Threats Across Stages

A critical aspect of Detection of an Evolving Threat is its focus on the [unified kill chain](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf), the sequential stages a threat actor typically traverses. From initial foothold to actions on objective, understanding the progression of threats through these stages is paramount. This principle allows us to not only identify isolated incidents but also to trace the entire trajectory of a potential threat.

#### Signal Sequencing: A Chronological Tapestry of Threat Indicators

Traditionally, detection signals have been treated as isolated events, lacking a chronological context. Detection of an Evolving Threat introduces the concept of signal sequencing, emphasizing the importance of understanding how multiple signals unfold over time. It's akin to weaving a chronological tapestry that tells a more comprehensive story of potential threats. This temporal sequencing provides a richer context, aiding in the differentiation between transient anomalies and orchestrated attacks. By considering the temporal aspect, we move beyond isolated events to understand the unfolding narrative of potential threats.

#### Contextual Awareness: Bridging Past and Present Threat Activities

Context is the key to effective threat assessment. Detection of an Evolving Threat introduces the concept of contextual awareness, which involves connecting ongoing threat activities to previously identified signals. This connection facilitates a more comprehensive understanding of the threat landscape. By linking current activities with historical signals, detection engineers and incident responders can discern patterns, uncover trends, and assess the potential evolution of threat actors' methodologies.

Detection engineers can employ the following strategies to implement Detection of an Evolving Threat effectively:

**Historical Analysis: Building a Repository of Context**

Maintaining a historical record forms the backbone of historical analysis in Detection of an Evolving Threat. This involves preserving signals and associated observables, such as actor, environment, and IP address, for reference and analysis. The historical context provides valuable insights into the evolution of threat actors' tactics, allowing for a more informed assessment of current signals. This repository of context-rich data aids in pattern recognition, enabling detection engineers to identify recurrent threats, understand their evolution, and proactively identify emerging patterns.

**Signal Correlation: Weaving a Coherent Narrative**

One of the primary strategies in implementing Detection of an Evolving Threat is through signal correlation. This involves the development of algorithms and rules that can correlate and link related signals, creating a coherent timeline of suspicious activities. The goal is to move beyond individual signals and understand how they interconnect over time. By weaving these signals into a chronological narrative, detection engineers can gain insights into the progression of potential threats. This interconnected view enhances the ability to identify orchestrated attacks and discern patterns that might be obscured when examining signals in isolation.

**Alert Prioritization: Strategic Ranking Along the Kill Chain**

In the context of Detection of an Evolving Threat, prioritizing alerts takes into account their position within the kill chain and the progression of the threat. Not all alerts are equal; some might indicate early reconnaissance, while others signal advanced stages of an attack. By strategically ranking alerts based on their relevance to the kill chain, incident responders can focus their attention on the most critical threats. This prioritization ensures that resources are allocated judiciously, enhancing the overall responsiveness of the team.

<!-- **Security Baselines: Understanding Normal Behavior**
Creating a baseline involves understanding normal behavior within a system or network, providing a benchmark against which current activities can be compared. This method enables detection engineers to identify anomalous activity effectively, as deviations from the established baseline can signal potential threats. By integrating security baselines into the detection strategy, we can enhance our ability to recognize evolving threats in their early stages. -->

**Machine Learning Integration: Automated Pattern Recognition**

As threats evolve, so should our detection capabilities. Machine learning integration is a key strategy as it empower us to identify subtle patterns and threat progression autonomously. This ensures that our detections mechanisms are not static and adapts dynamically to emerging threats.

## Realizing the Value of Detection of Evolving Threat

The efficacy of threat detection methodologies lies in their practical application. This section provides practical examples and case studies showcasing how we can successfully apply 2 of the previously mentioned strategies, Signal Correlation and Historical Analysis to identify and mitigate advanced threats.

### Signal Correlation in Action

The engagement with other departments that have in-depth knowledge of production systems, applications, and data is pivotal in developing the necessary understanding that bridges once-isolated signals. Threat intelligence information is also key to correlate individual signals with known threat actor profiles and their actions.

Illustrating this approach, the rules "Suspicious Activity in Atlassian Products" and "APT Related Activity in Atlassian Products" ingeniously combine signals from distinct data sources – Confluence, Bitbucket, and Jira. This correlation is instrumental in identifying suspicious activities across this suite of products, creating a timeline of executed actions within different kill chain stages. The former rule leverages "system" to cluster signals based on observables. In the case of "APT Related Activity in Atlassian Products," a threat actor profile, crafted from information gathered from threat intelligence, is employed to identify the actions of an APT group within Atlassian products. This rule combines signals from Confluence, Bitbucket, and Jira, offering a comprehensive view of the threat actor's maneuvers within this product suite.

```yaml
rule Suspicious Activity in Atlassian Products {
  signals:
    system_1 = Jira
    system_2 = Bitbucket
    system_3 = Confluence
    rule_1 = New Administrator
    rule_2 = Secrets Search
    rule_n = …
  condition:
    1 of $system_* and 3 of $rule_*
}
```

```yaml
rule APT Related Activity in Atlassian Products {
  signals:
    rule_1 = Secrets Search
    rule_2 = Anomalous Service Account Activity
    rule_3 = New Administrator
    rule_4 = Multiple Repositories Cloned or Archived by a Single Actor
    rule_n = ...
  condition:
    3 of them
}
```

### Mining Insights from the Past

Work in historical analysis with detection rules such as "Threat Found Through Historical Context" tap into the wealth of information embedded in past security findings generated by SIEM rules. This method involves clustering information based on observables such as actors or environments, offering a retrospective lens into threat activities. What's more, this process isn't confined to a singular tool; it can extend its reach by incorporating security findings from various sources, including EDR, and security incidents reported by collaborators (SIRTs). The synergy of historical analysis and diverse data sources paints a comprehensive picture of threat evolution.

```yaml
rule Threat Found Through Historical Context {
  signals:
    rule_1 = User's Multi-factor Authentication (MFA) Disabled
    rule_2 = New Administrator
    rule_n = …
  cluster:
    ip_address
    user_name
  condition:
    3 of them
}
```

## Challenges and Considerations

As we delve into the realm of Detection of an Evolving Threat, it's crucial to acknowledge that the path to enhanced security is not without its hurdles. In this section, we unravel the intricacies and potential stumbling blocks that come with implementing this dynamic approach. Beyond the theoretical elegance of sequencing signals and tracking threats along the kill chain, practical challenges emerge, demanding thoughtful consideration and strategies for mitigation.
Security findings that prove to be false positives can inadvertently inject inaccurate information into the implementation of Detection of an Evolving Threat. This not only undermines the reliability of the system but also demands robust mechanisms for identifying and filtering out false positives to maintain the effectiveness of the threat detection process.
Moreover, the presence of distinct data source schemas and varied alert output schema poses a challenge. This diversity hampers the establishment of a common language for threat detection and investigation, exacerbating the complexity of clustering security findings. The absence of a standardized framework can impede the seamless integration of data sources that produce security findings, hindering the holistic view necessary for comprehensive threat assessment.
Lastly, the challenge of fostering collaboration among diverse teams and ensuring effective communication between security, IT, and other relevant departments should not be underestimated. Developing a shared understanding of threat progression across different organizational units is integral to the success of Detection of an Evolving Threat. This requires robust communication channels, and relationships between security and other organizational areas.

## Conclusion: A Proactive Approach to Threat Detection

In the rapidly evolving landscape of cybersecurity, where threats are dynamic and adversaries continually adapt their tactics, the conventional paradigm of threat detection may prove to be insufficient. This blog post introduces a methodology – "Detection of an Evolving Threat" – designed to identify and mitigate advanced threats by tracing their progression along the kill chain. The journey through this blog post has unfolded key principles and strategies that collectively mark a paradigm shift for threat detection. Detection of an Evolving Threat heralds a proactive shift in threat detection methodologies. By tracking threats along the kill chain, detection engineers can provide early, context-rich alerts, empowering organizations to respond effectively to advanced adversaries.
