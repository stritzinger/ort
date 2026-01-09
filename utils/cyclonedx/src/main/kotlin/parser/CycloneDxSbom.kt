/*
 * Copyright (C) 2025 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.utils.cyclonedx.parser

import java.io.File

import org.cyclonedx.model.Bom
import org.cyclonedx.model.Component
import org.cyclonedx.parsers.JsonParser

import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.utils.cyclonedx.CycloneDxDependency

/**
 * Result of parsing a CycloneDX SBOM file.
 */
data class CycloneDxParsedSbom(
    val bom: Bom,
    val dependencies: List<CycloneDxDependency>,
    val aliasToCanonicalRef: Map<String, String>,
    val dependenciesByRef: Map<String, List<String>>,
    val rootRef: String?,
    val issues: List<Issue>
)

/**
 * Parser for CycloneDX SBOM files.
 */
object CycloneDxSbom {
    /**
     * Parse a CycloneDX JSON SBOM file and extract dependency information.
     *
     * @param definitionFile The CycloneDX JSON file to parse.
     * @param source The source identifier for issues (typically the package manager name).
     * @return A [CycloneDxParsedSbom] containing the parsed BOM, dependencies, and any issues.
     * @throws Exception if the SBOM file cannot be parsed.
     */
    fun parse(definitionFile: File, source: String): CycloneDxParsedSbom {
        val issues = mutableListOf<Issue>()

        // Let exceptions propagate - the package manager will handle them.
        val bom = JsonParser().parse(definitionFile)

        val aliasToCanonicalRef = buildAliasToCanonicalRefMap(bom, source, issues)
        val dependenciesByRef = buildDependenciesByRef(bom, aliasToCanonicalRef)
        val allDependencies = buildDependencies(bom, aliasToCanonicalRef, dependenciesByRef, source, issues)
        val rootRef = extractRootRef(bom, aliasToCanonicalRef)

        validateDependencyGraph(allDependencies, dependenciesByRef, rootRef, source, issues)

        return CycloneDxParsedSbom(
            bom = bom,
            dependencies = allDependencies,
            aliasToCanonicalRef = aliasToCanonicalRef,
            dependenciesByRef = dependenciesByRef,
            rootRef = rootRef,
            issues = issues
        )
    }

    private fun fingerprint(component: Component): String =
        listOf(
            component.type?.name,
            component.group,
            component.name,
            component.version,
            component.purl,
            component.bomRef
        ).joinToString("|") { it.orEmpty() }

    private fun buildAliasToCanonicalRefMap(bom: Bom, source: String, issues: MutableList<Issue>): Map<String, String> {
        val aliasToCanonicalRef = mutableMapOf<String, String>()
        val canonicalToFingerprint = mutableMapOf<String, String>()

        bom.components.orEmpty().forEach { component ->
            val bomRef = component.bomRef
            val purl = component.purl

            // Prefer purl over bomRef as canonical since it's more stable and identifying.
            val preferredCanonical = purl ?: bomRef ?: return@forEach

            val fp = fingerprint(component)
            val existingFp = canonicalToFingerprint[preferredCanonical]

            // If two different components map to the same canonical, avoid merging nodes silently by falling back to
            // bomRef.
            val canonical = if (existingFp != null && existingFp != fp) {
                issues += Issue(
                    source = source,
                    severity = Severity.WARNING,
                    message = "Canonical ref collision for '$preferredCanonical': multiple components map to the " +
                        "same canonical identifier (likely missing version or producer issue). Falling back to " +
                        "'bom-ref' for the colliding component when possible."
                )
                bomRef ?: preferredCanonical
            } else {
                preferredCanonical
            }

            canonicalToFingerprint.putIfAbsent(canonical, fp)

            // Map all known aliases (bomRef + purl) to the chosen canonical.
            listOfNotNull(bomRef, purl).distinct().forEach { alias ->
                val existing = aliasToCanonicalRef[alias]
                if (existing != null && existing != canonical) {
                    issues += Issue(
                        source = source,
                        severity = Severity.WARNING,
                        message = "Alias '$alias' maps to multiple canonical refs ('$existing' and '$canonical'). " +
                            "Keeping '$existing'."
                    )
                } else {
                    aliasToCanonicalRef[alias] = canonical
                }
            }
        }

        return aliasToCanonicalRef.toMap()
    }

    private fun buildDependenciesByRef(bom: Bom, aliasToCanonicalRef: Map<String, String>): Map<String, List<String>> {
        val rawdependenciesByRef: Map<String, List<String>> = bom.dependencies?.associate { dep ->
            dep.ref to (dep.dependencies?.map { it.ref } ?: emptyList())
        } ?: emptyMap()

        return rawdependenciesByRef
            .map { (parentRef, childRefs) ->
                val canonicalParent = aliasToCanonicalRef[parentRef] ?: parentRef
                val canonicalChildren = childRefs.map { aliasToCanonicalRef[it] ?: it }
                canonicalParent to canonicalChildren
            }
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, lists) ->
                lists.flatten()
                    .distinct()
                    .sorted() // deterministic output
            }
    }

    private fun buildDependencies(
        bom: Bom,
        aliasToCanonicalRef: Map<String, String>,
        dependenciesByRef: Map<String, List<String>>,
        source: String,
        issues: MutableList<Issue>
    ): List<CycloneDxDependency> {
        return bom.components.orEmpty().mapNotNull { component ->
            val ref = component.bomRef ?: component.purl
            if (ref == null) {
                issues += Issue(
                    source = source,
                    message = "Dependency '${component.name}' has neither 'bom-ref' nor 'purl'; skipping it."
                )
                return@mapNotNull null
            }

            val canonicalRef = aliasToCanonicalRef[ref] ?: ref

            CycloneDxDependency(
                component = component,
                bomRef = canonicalRef,
                dependsOn = dependenciesByRef[canonicalRef].orEmpty()
            )
        }
    }

    private fun extractRootRef(bom: Bom, aliasToCanonicalRef: Map<String, String>): String? {
        val rawRootRef = bom.metadata?.component?.bomRef ?: bom.metadata?.component?.purl
        return rawRootRef?.let { aliasToCanonicalRef[it] ?: it }
    }

    private fun validateDependencyGraph(
        allDependencies: List<CycloneDxDependency>,
        dependenciesByRef: Map<String, List<String>>,
        rootRef: String?,
        source: String,
        issues: MutableList<Issue>
    ) {
        val validBomRefs = buildSet {
            addAll(allDependencies.map { it.bomRef })
            rootRef?.let { add(it) }
        }

        val graphRefs = buildSet {
            dependenciesByRef.forEach { (parent, children) ->
                add(parent)
                children.forEach { add(it) }
            }
        }

        val missingInComponents = graphRefs - validBomRefs
        if (missingInComponents.isNotEmpty()) {
            issues += Issue(
                source = source,
                message = "SBOM dependency graph contains ${missingInComponents.size} ref(s) that do not " +
                    "match any component 'bom-ref' or 'purl'.",
                severity = Severity.WARNING
            )
        }

        allDependencies.forEach { dependency ->
            dependency.dependsOn.forEach { referencedBomRef ->
                if (referencedBomRef !in validBomRefs) {
                    issues += Issue(
                        source = source,
                        message = "Dependency '${dependency.component.name}' references missing ref " +
                            "'$referencedBomRef' in the dependency graph."
                    )
                }
            }
        }
    }

    /**
     * Extract project metadata from a CycloneDX BOM's metadata component.
     */
    fun projectMetadata(bom: Bom): CycloneDxProjectMetadata? {
        val metadataComponent = bom.metadata?.component ?: return null

        val authorsFromAuthorsArray: Set<String> =
            metadataComponent.authors.orEmpty()
                .mapNotNull { it.name ?: it.email }
                .filter { it.isNotBlank() }
                .toSet()

        val manufacturerName: Set<String> =
            metadataComponent.manufacturer?.name
                ?.takeIf { it.isNotBlank() }
                ?.let { setOf(it) }
                ?: emptySet()

        val legacyAuthor: Set<String> =
            metadataComponent.author
                ?.takeIf { it.isNotBlank() }
                ?.let { setOf(it) }
                ?: emptySet()

        val authors: Set<String> =
            (authorsFromAuthorsArray + manufacturerName).ifEmpty { legacyAuthor }

        return CycloneDxProjectMetadata(
            name = metadataComponent.name.orEmpty(),
            namespace = metadataComponent.group.orEmpty(),
            version = metadataComponent.version.orEmpty(),
            description = metadataComponent.description.orEmpty(),
            authors = authors,
            declaredLicenses = metadataComponent.licenses?.licenses?.mapNotNull {
                it.id ?: it.name
            }?.toSet() ?: emptySet(),
            homepageUrl = metadataComponent.externalReferences?.find {
                it.type == org.cyclonedx.model.ExternalReference.Type.WEBSITE
            }?.url.orEmpty(),
            vcsUrl = metadataComponent.externalReferences?.find {
                it.type == org.cyclonedx.model.ExternalReference.Type.VCS
            }?.url.orEmpty()
        )
    }
}

/**
 * Project metadata extracted from a CycloneDX BOM.
 */
data class CycloneDxProjectMetadata(
    val name: String,
    val namespace: String,
    val version: String,
    val description: String,
    val authors: Set<String>,
    val declaredLicenses: Set<String>,
    val homepageUrl: String,
    val vcsUrl: String
)
