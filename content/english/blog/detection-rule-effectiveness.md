---
title: "Maximizing Threat Detection Rule Effectiveness"
meta_title: ""
# description: "this is meta description"
date: 2023-03-10
image: "images/detection-rule-effectiveness/rules_performace_metrics.jpeg"
categories: ["Security"]
author: "ardroci"
tags: ["Threat Detection", "Rule", "Metrics"]
draft: false
---

# Maximizing Threat Detection Rule Effectiveness

As security detection engineers, we constantly strive to enhance the effectiveness of our threat detection rules. While constructing a confusion matrix from the Security Incident Response Team (SIRT) investigation's dispositions—true positives, benign events, and false positives—provides insights, it's crucial to establish robust performance metrics for a comprehensive assessment.

## Understanding the Challenge

Threat detection rules operate in a binary classification problem, categorizing events as malicious or benign. However, the imbalance in data sources—where the negative class significantly outweighs the positive class—necessitates careful selection of evaluation metrics. Metrics relying heavily on true negative results may not accurately reflect real-world performance.

## Performance Metrics for Detection Rules

### False Negative Rate

The false negative rate quantifies the proportion of malicious behavior that eluded detection. Think of it as the fraction of fraudulent transactions missed by our model. If the consequences of letting fraudulent transactions slip through are substantial, and the value derived from users isn't significant, focusing on minimizing this number becomes crucial. Our goal is clear: optimize the false negative rate to 0% to ensure we capture all malicious activity.

<div style="text-align:center"><img src="images/detection-rule-effectiveness/fnr.png" alt="False Negative Rate Equation"/></div>

### False Discovery Rate

The false discovery rate measures the proportion of incorrect evaluations among all rule matches. Increasing false alerts consumes valuable time, and we want all positive matches to merit investigation. Therefore, our aim is to optimize for precision, ensuring that each positive match is indeed worth examining.

<div style="text-align:center"><img src="images/detection-rule-effectiveness/fdr.png" alt="False Discovery Rate Equation"/></div>

### Recall | Sensitivity | True Positive Rate

Recall reflects the proportion of correctly identified rule matches. It answers the question: How many fraudulent transactions did we correctly recall out of all fraudulent transactions? Recall becomes pivotal when catching all fraudulent transactions is paramount, even at the cost of some false alerts. If recall is lower, it implies we're missing true positive results due to incorrect or over-tuned detection logic. Our target is to optimize recall to 100% to ensure we identify all malicious activity.

<div style="text-align:center"><img src="assets/images/detection-rule-effectiveness/tpr.png" alt="True Positive Rate Equation"/></div>

### Precision | Positive Predictive Value

Precision reveals the ratio of correctly classified positive identifications. In the context of fraud detection, precision indicates the proportion of transactions correctly labeled as fraudulent. When optimizing precision, we want to ensure that those we deem guilty are truly so. Our goal is to optimize precision to 95%, striking a balance between identifying all malicious activity and ensuring positive predictions warrant scrutiny.

<div style="text-align:center"><img src="images/detection-rule-effectiveness/ppv.png" alt="Positive Predictive Value Equation"/></div>

### Fbeta Score

The Fbeta score amalgamates precision and recall into a single metric. A higher Fbeta score signifies better detection rule performance. The choice of beta in the Fbeta score reflects our prioritization between recall and precision. For instance, with an F2 score, recall is twice as important as precision. Our objective is to optimize the F2 score to 95%, emphasizing the importance of recall while maintaining a high level of precision.

<div style="text-align:center"><img src="images/detection-rule-effectiveness/fbeta.png" alt="Fbeta Score Equation"/></div>

# Evaluating Performance and Defining Tune Priorities

Once we've established the key performance metrics for our detection rules, the next step is to evaluate their performance and define tune priorities. By categorizing rule performance and prioritizing optimization efforts, we can effectively allocate resources and enhance our threat detection rules.

| **Performance Rank** | **Tune Priority** | **Conditions**                                                                                                                           | **Description**                                                                                                                                                                                |
| -------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Good                 | -                 | False Negative Rate = 0 && False Discovery Rate < 0.05 && F2 score >= 0.95                                                               | The detection rule is capturing all true positive results, with a very low rate of false positive results.                                                                                     |
| Average              | High              | False Negative Rate = 0 && False Discovery Rate > 0.05 && F2 score >= 0.95                                                               | The detection rule is capturing all true positive results, but is creating some false positive results.                                                                                        |
| Poor                 | Critical          | (False Discovery Rate > 0.05 \|\| Precision < 0.95) && F2 score < 0.95                                                                   | The detection rule is underperforming.                                                                                                                                                         |
| Bad                  | Urgent            | False Negative Rate > 0 \|\|<br>False Discovery Rate = 1 \|\|<br>F2 score >= 0.95 && (False Discovery Rate > 0.05 \|\| Precision < 0.95) | The detection rule is missing true positive results.<br>The detection rule only created false positive results.<br>The detection rule is creating a high percentage of false positive results. |

In conclusion, by adopting a systematic approach to performance evaluation and optimization, we enhance the effectiveness of our threat detection rules. Establishing clear priorities based on performance evaluations empowers us to allocate resources efficiently and address deficiencies proactively. Through continuous improvement, we fortify our security posture and stay resilient against evolving threats.

## Bed Time Reading

1. [Classification: Accuracy](https://developers.google.com/machine-learning/crash-course/classification/accuracy)
2. [Precision and recall](https://developers.google.com/machine-learning/crash-course/classification/precision-and-recall)
3. [24 Evaluation Metrics for Binary Classification (And When to Use Them)](https://neptune.ai/blog/evaluation-metrics-binary-classification)
