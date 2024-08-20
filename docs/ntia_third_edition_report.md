# NTIA Third Edition Draft Conclusion

## Problem Statement

- **Complex and Dynamic Supply Chains**:
  - Modern software systems are built using a wide array of components, libraries, and dependencies, often sourced from multiple vendors and open-source communities. These components are frequently updated and may have varying levels of quality and security.
  - The "*dynamic*" nature refers to the *constant changes and updates in these components*, which can introduce new risks or dependencies.

- **Contributing to Cybersecurity Risk**:
  - The **absence of visibility** (i.e., lack of SBOMs) into software components increases the risk of security breaches. For example, a vulnerability in a third-party library might go unnoticed, leaving the entire system vulnerable to attacks.
  - Cybersecurity threats can originate from unpatched software, insecure dependencies, or malicious code introduced through supply chain attacks.

- **Impact on Collective Goods**:
  - In critical systems (e.g., healthcare, transportation, energy), vulnerabilities can lead to severe consequences, affecting public safety.
  - Compromised software in government or defense systems can lead to breaches that threaten national security.

The problem statement highlights the challenges posed by the complexity and lack of visibility in modern software supply chains. These challenges contribute to increased cybersecurity risks and higher costs, with potential impacts on public safety and national security. Addressing these issues requires better visibility into software composition and functionality to mitigate risks and manage costs effectively.

**Conclusion**: Complex Software → built from a wide array of components, libraries, and dependencies → lack of visibility in these components, libraries, and dependencies → can cause cybersecurity risks → risks can turn into cybersecurity attacks → these attacks can affect interconnected systems such as healthcare, transportation, and energy. Example: CrowdStrike.

## Solution

- Increasing transparency in software supply chains (components, libraries, and dependencies) using SBOMs can reduce cybersecurity risks and overall costs. Let's understand the benefits of increased transparency in software supply chains:
  - Identify vulnerable components, libraries, and dependencies.
  - Detect suspicious or counterfeit software components.

## Why NTIA?

- To address the **problem of poor software supply chain transparency**, the National Telecommunications and Information Administration (NTIA) was formed.

## NTIA Goals

- To achieve greater supply chain transparency, the primary goal is to create a model for software component information that can be shared universally across different industry sectors. The main purpose of the model is to increase transparency in the software supply chain.
- But how does the model increase transparency in the software supply chain?
  - The model specifically focuses on defining and describing a Software Bill of Materials (SBOM), which is a detailed inventory or list of all components, libraries, and dependencies that make up a software product.
  - The model addresses how different software components are related to each other within the software system. Understanding these relationships is crucial for identifying dependencies and potential vulnerabilities.

## SBOM

- SBOM is the implementation of the above model.
- An SBOM (Software Bill of Materials) is a formal, machine-readable inventory that details the software components and dependencies that make up a software product.
- The SBOM is described as a "nested inventory," meaning it’s like a list of ingredients for a recipe. Just as a recipe lists all the ingredients needed to make a dish, the SBOM lists all the components required to create the software.
- The SBOM describes all components, their dependencies, and the relationships between components.
- It’s not just a simple list; it’s structured in a way that machines (software tools) can easily read, process, and analyze.
- At a minimum, baseline attributes are required in SBOMs.

## Baseline Attributes

- The **primary goal of an SBOM** is to uniquely and clearly identify software components and their relationships. To achieve this, the SBOM relies on a set of baseline attributes. The required baseline attributes are:
  - **Author Name**: Who created the SBOM
  - **Timestamp**: When the SBOM was generated.
  - **Primary Component** (or Root of Dependencies): The main software component or the root from which dependencies are identified.

The Author Name, Timestamp, and Primary Component (or Root of Dependencies) attributes provide **meta-information about an SBOM**, and the remaining attributes apply to components that are direct or transitive dependencies of the Primary Component. Some baseline attributes discussed in this document align with the necessary Data Field elements outlined in the "Minimum Elements for a Software Bill of Materials (SBOM)" document. The document introduces the concept of **data maturity levels** for certain attributes, categorized into three levels:

- **Minimum Expected**: Must meet globally.
- **Recommended Practice**: Best practices.
- **Aspirational Goal**: Future-oriented practices.

**Note**: If there are no maturity levels for the attribute, the instructions presented are the minimum expected.

### SBOM Meta-Information

- **Author Name** (Must) (Supported by sbomqs):
  - Minimum:
    - If multiple participants were involved in creating the SBOM, the Author Name attribute should list all of them. For example, if different organizations, teams, or individuals contributed to the SBOM, they should all be named.
    - The entity that created the SBOM data. This helps trace the origin of the SBOM information.
    - Note: The Author Name may differ from the Supplier Name of the primary component, indicating that the SBOM was not created by the supplier.
  - Recommended:
    - Include the tools and their versions that assisted in the SBOM creation.

- **Timestamp** (Must) (Supported by sbomqs):
  - Minimum:
    - The Timestamp is the date and time that the SBOM was created, formatted as `YYYY-MM-DDThh:mm:ssZ` (e.g., 2024-05-23T13:51:37Z).

- **Type** (Optional) (Supported by sbomqs for CycloneDX):
  - Aspirational Goal:
    - The Type attribute provides context for how and why the SBOM was created.
    - Documenting the SBOM Type may inform the utility and consumption of the SBOM.

- **Primary Component** (or Root of Dependencies) (Must) (Supported by sbomqs):
  - The Primary Component, also referred to as the root of dependencies, is the main software component that the SBOM describes and from which all other components (dependencies) originate.

After identifying an SBOM’s Primary Component and its attributes in the SBOM meta-information, the next step in developing an SBOM is to uniquely enumerate top-level components that a supplier directly includes in the Primary Component.

### Component Attributes

- **Component Name** (Must) (Supported by sbomqs):
  - The public name for a component defined by its original supplier or creator.
  - Component (and Supplier) Names can also be conveyed using a generic **namespace:name** construct.

- **Version** (Must) (Supported by sbomqs):
  - The version specifies the iteration or update of the software being referred to.
  - Semantic versioning is preferred, e.g., `1.0.0`, `2.1.3`:
    - Format: "major.minor.patch".
  - Git hashes are also acceptable.

- **Supplier Name** (Must) (Supported by sbomqs, but doesn't cover all cases):
  - It is the entity that creates, defines, and identifies a component.
  - Possible Cases:
    - Unmodified Software Components:
      - Commercial Software:
        - Legal Entity name of the upstream supplier.
        - If it’s not globally unique, add the jurisdiction.
        - If the Legal Entity name is unknown, use the vendor name from the NIST CPE.
      - Open Source Software:
        - Project name (with the host foundation, if known).
      - For Supplier Difficult to Identify:
        - Use domain URL/PURL namespace or mark as "unknown."
    - Modified Software Components:
      - Use the name of the modifying supplier and document the original supplier separately.

- **Unique Identifier** (Must) (Supported by sbomqs):
  - Unique identifiers provide additional information to help uniquely define a component.
  - Publicly available identifiers:
    - Common Platform Enumeration (CPE).
    - Package URL (PURL).
  - Organization-specific identifiers:
    - Software Identification (SWID) Tags.
    - Universal Unique Identifier (UUID) (also known as Globally Unique Identifier [GUID]).
    - Software Heritage ID (SWHID).
    - OmniBOR Artifact IDs (formerly known as Gitoid Namespace Relative IDs).

- **Cryptographic Hash** (Must) (Supported by sbomqs):
  - Ensures that the component has not been tampered with or altered.
  - Digital signatures can offer stronger guarantees of integrity and authenticity compared to hashes, but they come with added complexities such as key management and signature verification.
  - Minimum:
    - Provide a hash for the compiled binary form of that component.
    - Accepted hash algorithms include MD5, SHA-1, and SHA-256.
  - Recommended Practice:
    - Provide a hash of the Primary Component.
    - Use secure hash algorithms, such as SHA-256 or higher.

- **Relationship** (Must) (Supported by sbomqs, needs review):
  - Minimum:
    - Describes the association of a component listed within the SBOM to other components.
    - Relationships should be declared between the Primary Component (the main component the SBOM describes) and its **direct dependencies**.
  - Recommended Practice:
    - Declare relationships for all components listed in the SBOM, e.g., "Included Relationship".
  - Aspirational Goal:
    - List all dependencies of components, whether they are listed in the SBOM or not.

### Types of Common Relationships to Declare in the SBOM

- **Primary Relationship**:
  - The "Primary Relationship" refers to the relationship type used when a component is the main focus or subject of the SBOM. This component is known as the "primary component," and it is central to the SBOM's purpose. For example, if the SBOM is created for a specific application (like "Acme Application" in Table 2), that application is the primary component.
- **Included In” Relationship**:
  - The "Included In" Relationship describes how components within an SBOM are related to one another.
  - Example:
    - Acme Application v1.1 includes Bob’s Browser 2.1.
      - This means Acme Application version 1.1 depends on or includes Bob’s Browser version 2.1.
  - For components the type of relationship to be look is included or contains. Realtionship b/w each other components presnet in sbom such as "included" or "contain".
- **Heritage or Pedigree Relationship**
  - it helps track the origin and modification history of a software component.
  - For example:
    - You fork an open-source project (let’s call it "Project X") to make contributions. Your forked version (let’s call it "Project X-Fork") is a new component derived from the original "Project X".
  - After making changes and contributions to "Project X-Fork", these changes are merged back into the upstream project, "Project X".
  - "Project X-Fork" should have a heritage or pedigree relationship with "Project X",
  - "Project X-Fork" → "GENERATED_FROM" → "Project X": Indicates that "Project X-Fork" was created from "Project X".
  - "Project X" → "INCLUDES" → "Project X-Fork": After merging, "Project X" includes the contributions made in "Project X-Fork".
  - SPDX supports GENERATED_FROM and DESCENDANT_OF relationship types, while CycloneDX supports “pedigree” relationships.

- **Relationship Assertions** (Must) (Supported by sbomqs, needs review):
  - In cases, SBOM authors might assert their beliefs or understanding about these upstream components based on available information, even if it's not fully authoritative.
  - SBOM authors may want to make non-authoritative claims or assertions about components for which the authors are not the suppliers.
  - Categories for Relationship Assertions
    - Unknown
      - No information about upstream components is provided; assumes potential unknowns.
    - None
      - A clear statement by the supplier that no upstream components exist for this particular component.
    - Partial
      - There is some knowledge about immediate upstream components, but not complete information.
    - Known
      - The complete set of immediate upstream relationships is fully identified and listed.
  
- **License**
  - Identifies the legal terms for software use, modification, and distribution.
  - Recommended Practice:
    - Provide detailed license information (full name, identifier, text, URL) for as many components as possible, using tools to manage open-source licenses.
  - Aspirational Goal:
    - Provide detailed license information for all components in the SBOM and include an attestation of the license information's accuracy.

- ***Copyright Holder**  - must - (not supported by sbomqs while scoring)
  - The Component Copyright Holder is the entity that legally owns the copyright for the component listed in the SBOM.
  - Minimum Expected
    - Provide copyright information for the Primary Component only.
  - Recommended Practice
    - Provide copyright information for any other component where this information is available from the supplier or a tool used for managing SBOMs.
  - Aspirational Goal
    - Ensure that all components listed in the SBOM have their copyright information entered.
