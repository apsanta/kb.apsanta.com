---
description: Analyzing scan results of C# SAST tools
---

# Show me your Pull Request

It is a good time to develop a new open-source project. Many tools provide a special tier for public repositories allowing for scanning without limits.&#x20;

And you also have some "free" tools. Maybe they are not fancy but they can do its job, right?

What we have on the table:

* Visual Studio IDE Roslyn Analyzers
* Puma Scan Free
* Security Code Scan
* SonarAnalyzer.CSharp
* Sonar Cloud
* Codacy Security Scan
* Semgrep Community
* Code QL (Github Advanced Security)

What are we going to test? I created a new public repo specifically for this need - [Julieta](https://github.com/dbalikhin/julieta). It is a reference to a well-known test suite from [NIST](https://samate.nist.gov/SRD/testsuite.php). **NIST Juliet** Test Suite for C# is great with an astonishing number of test cases - 28942! However, while it is great on paper, it is not very practical. These tests are very synthetic, cover legacy versions and are a great source of what can go wrong.&#x20;

My test suite **Julieta **is a simple .NET Core project with some Controller classes. I'm more interested in testing within a PR, so having a web project is handy. Another reason: some scanners may have a very minimal list of sources. If code comes from a web controller, it should trigger all scanners!

**Visual Studio IDE Roslyn Analyzers** are from the [roslyn-analyzers repo](https://github.com/dotnet/roslyn-analyzers). It is a part of .NET Core 5 SDK meaning you don't need to install them manually for any .NET Core 5 or higher project. If you want to use them in other versions, add `Microsoft.CodeAnalysis.NetAnalyzers` nuget package.

**Puma Scan Free **and **Codacy Security Scan **are both using Roslyn Compiler API. It would be interesting to compare the results with VS IDE Roslyn Analyzers.

**SonarAnalyzer.CSharp** package contains a subset of all rules available in SonarCloud. It is available for free and **Codacy Security Scan** is based on these rules. There are 72 security rules according to Codacy.

**Sonar Cloud **is a cloud version of Sonar Qube. It is very close to Sonar Qube Dev Edition (same price and features including** taint analysis** which means extra rules compared to SonarAnalyzer.CSharp and Codacy).

**Semgrep Community **is a very promising SAST tool. You can create custom [rules ](https://semgrep.dev/docs/writing-rules/overview/)with a very easy "yaml-like" language. The guys and gals behind **semgrep **reviewed all available free/open-source rules and created a very lightweight scanner. Your custom rules need to be public (contribute to community edition), otherwise, you need to pay for Team Edition with private rules.

{% code title="using insecure function" %}
```yaml
rules:
  - id: react-dangerouslysetinnerhtml
    languages:
      - typescript
      - javascript
    message: >
      Setting HTML from code is risky because it’s easy to inadvertently expose
      your users to a cross-site scripting (XSS) attack.
    pattern-either:
      - pattern: |
          <$X dangerouslySetInnerHTML=... />
      - pattern: |
          {dangerouslySetInnerHTML: ...}
    severity: WARNING

```
{% endcode %}



**Code QL (Github Advanced Security) **is a SAST monster. Github acquired **Semmle **company in Sep 2019. Previously Code QL was known as **LGTM**. There are a lot of videos about LGTM. Semmle developed a scanner where you can write your own rules - **queries**.  They call it **variant analysis **(the process of using a known security vulnerability as a seed to find similar problems in your code.), but technically it is just an ability to issue very powerful custom queries. You can use the standard CodeQL queries to identify seed vulnerabilities or find new vulnerabilities by writing your own custom CodeQL queries. More info is [**here.**](https://codeql.github.com/docs/writing-codeql-queries/codeql-queries/)****

{% code title="SQL Injection Query" %}
```sql
/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cs/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import csharp
import semmle.code.csharp.security.dataflow.SqlInjectionQuery
import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
import semmle.code.csharp.security.dataflow.flowsources.Remote
import semmle.code.csharp.security.dataflow.flowsources.Local

string getSourceType(DataFlow::Node node) {
  result = node.(RemoteFlowSource).getSourceType()
  or
  result = node.(LocalFlowSource).getSourceType()
}

from TaintTrackingConfiguration c, DataFlow::PathNode source, DataFlow::PathNode sink
where c.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Query might include code from $@.", source,
  ("this " + getSourceType(source.getNode()))
```
{% endcode %}

