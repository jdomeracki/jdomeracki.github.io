---
layout: post
title: Hunting for Bucket Traversals in Google's Client Libraries
---

## Table of Contents
- [Preface](#preface)
- [Bucket Traversal 101](#bucket-traversal-101)
- [Case study](#case-study)
    * [TL;DR](#tldr)
    * [Overview](#overview)
    * [Technical analysis](#technical-analysis)
    * [PoC](#poc)
    * [Attack scenario](#attack-scenario)
    * [Diagram of a sample vulnerable application](#diagram-of-a-sample-vulnerable-application)
- [Summary](#summary)

---

## Preface
This writeup picks up pretty much where the last one ended, that is when I found an exploitable instance of a [bucket traversal](https://jdomeracki.github.io/2024/11/09/sketchy_cheat_sheet/#bucket-traversal) vulnerability and [stumbled on an N-day in Go Cloud Storage client library](https://jdomeracki.github.io/2024/11/09/sketchy_cheat_sheet/#stumbling-on-an-n-day-in-go-cloud-storage-client-library).

Intrigued by this finding, I decided to audit other [Cloud Storage client libraries](https://cloud.google.com/storage/docs/reference/libraries) focused solely on variants of similar issues.

---

## Bucket Traversal 101
So what is a _Bucket Traversal_ to begin with?

Asked Gemini 2.5 to do the heavy lifting:\
[_A Bucket Traversal Vulnerability is a class of security weaknesses where an application improperly handles user-supplied input when interacting with cloud storage services (like AWS S3, Google Cloud Storage, Azure Blob Storage, etc.). This flaw allows an attacker to manipulate the input (typically filenames, paths, or object keys) to access or sometimes modify objects within a storage bucket that they are not intended to have access to._](https://g.co/gemini/share/d0849a9e5a62)

The above definition is not wrong but it doesn't mention the vital Cloud IAM prerequisite, which also has to be met:\
**_The Service Account (non-human identity) attached to the targed workload, has to be granted IAM permissions to read/write/edit bucket(s) other than the intended one_**

For the purpose of this writeup, I will differentiate between two subsets of bucket traversal issues:
1. Application level ie. faulty business logic, lack of input validation etc.
2. Library level ie. security bugs in opinionated SDKs often maintained by Cloud Service Providers

There is little I could add to what practices could prevent issues from `#1` (AppSec 101)\
Therefore, I will focus primarily on class `#2`, that is when the implementation of the vendor maintained library is vulnerable itself.

---

## Case study

### TL;DR
The method [google.cloud.storage.transfer_manager.upload_chunks_concurrently()](https://github.com/googleapis/python-storage/blob/d5d3c68a6e5c6f8cefc59892c1ccceaf181ff32d/google/cloud/storage/transfer_manager.py#L956) was vulnerable to a variant of a path (bucket) traversal.

Timeline:
- Faulty function was [introduced](https://github.com/googleapis/python-storage/pull/1115/files
) in version [2.11.0](https://github.com/googleapis/python-storage/releases/tag/v2.11.0) on `September 19th 2023`
- I submitted this issue to Google VRP on `July 14th 2024`
- The vulnerability was [fixed](https://github.com/googleapis/python-storage/commit/bf4d0e0a2ef1d608d679c22b13d8f5d90b39c7b2) in version [2.18.1](https://github.com/googleapis/python-storage/releases/tag/v2.18.1) on `August 6th 2024`

Here's the recently disclosed report -> https://bughunters.google.com/reports/vrp/h1K5SciPh
> Why is there no GitHub Security Advisory (GHSA) and/or CVE published you might wonder (?)\
> Well that's a topic for a separate discussion - I was told that at least a post factum comment will be eventually added.

---

### Overview
[Python Client for Google Cloud Storage()](https://cloud.google.com/python/docs/reference/storage/latest) is an Open Source project maintained by Google.

Excerpt from docs:\
_[Client libraries make it easier to access Google Cloud APIs from a supported language. While you can use Google Cloud APIs directly by making raw requests to the server, client libraries provide simplifications that significantly reduce the amount of code you need to write.](https://cloud.google.com/apis/docs/client-libraries-explained#:~:text=Client%20libraries%20make%20it%20easier%20to%20access%20Google%20Cloud%20APIs%20from%20a%20supported%20language.%20While%20you%20can%20use%20Google%20Cloud%20APIs%20directly%20by%20making%20raw%20requests%20to%20the%20server%2C%20client%20libraries%20provide%20simplifications%20that%20significantly%20reduce%20the%20amount%20of%20code%20you%20need%20to%20write.)_

This library is used in many foundational Python-based ML/AI Open Source projects such as:
- [Kubeflow](https://grep.app/search?f.repo.pattern=kubeflow&q=from+google.cloud+import+storage)
- [Mlflow](https://grep.app/search?f.repo=mlflow%2Fmlflow&f.repo.pattern=mlflow&q=from+google.cloud+import+storage)
- [Ray](https://grep.app/search?f.repo.pattern=ray&q=from+google.cloud+import+storage)

> The relatively modest number of stars on GitHub does not properly reflects its significance

---

### Technical analysis
Google Cloud Storage exposes three distinct APIs:
- [JSON](https://cloud.google.com/storage/docs/json_api)
- [XML](https://cloud.google.com/storage/docs/xml-api/overview)
- [RPC](https://cloud.google.com/storage/docs/reference/rpc/storage-operations)

I decided to focus on the XML API due to its subjectively [error prone schema](https://cloud.google.com/storage/docs/request-endpoints#xml-api) & [interoperability with Amazon Simple Storage Service (Amazon S3)](https://cloud.google.com/storage/docs/interoperability#xml_api)

After some brief source code review & grey box testing, I pinpointed a spot where a traversal could occur:\
https://github.com/googleapis/python-storage/blob/d5d3c68a6e5c6f8cefc59892c1ccceaf181ff32d/google/cloud/storage/transfer_manager.py#L1084-L1087

Issue stemmed from the fact that the URL path was constructed insecurely (lack of context specific encoding)
```python
    url = "{hostname}/{bucket}/{blob}".format(
        hostname=hostname, bucket=bucket.name, blob=blob.name
    )
```

As a result, if `blob.name` was supplied from user input, then an attacker could make use of the classic *dot-dot-slash* technique and upload a file to a bucket unintended by the victim eg. `../bucket/object`

---

### PoC
Here's the orginal PoC recording, based on the official [sample snippet](https://github.com/googleapis/python-storage/blob/main/samples/snippets/storage_transfer_manager_upload_chunks_concurrently.py)
<iframe src="https://drive.google.com/file/d/1_NAaJ-PjQRy7kcEJ4NW7sZ-YdfF79S5g/preview" width="640" height="480" allow="autoplay"></iframe>

---

### Attack scenario
Depending on the IAM permissions granted to the underlying Service Account this could lead to malicious scenarios such as:
1. overwriting existing files (data & integrity loss)
2. upload of an object later consumed by the application (config override, XSS etc.)

Potential impact associated with vector `#1` is self evident.\
I think that scenario `#2` is far more interesting.

---

### Diagram of a sample vulnerable application

Prepared a diagram of a sample vulnerable application `GigaUpload` to better convey the idea.

This fictitious service meets following criteria:
* large file upload implemented using google.cloud.storage.transfer_manager.upload_chunks_concurrently()   
* client side behaviour (features, flags etc.) managed via config files fetched from a dedicated GCS bucket

<p align="center">
<a href="https://storage.googleapis.com/bucket_traversals/giga_upload_bucket_traversal_diagram.png" target="_blank">
  <img src="https://storage.googleapis.com/bucket_traversals/giga_upload_bucket_traversal_diagram.png"/>
</a>
</p>

---

## Summary
Bucket traversal appears to be an underresearched class of vulnerabilities, requiring significant context-specific knowledge for comprehensive understanding.\
It exists at the intersection of traditional Application Security (AppSec) and Cloud Security, underscoring the critical need to integrate these two domains.