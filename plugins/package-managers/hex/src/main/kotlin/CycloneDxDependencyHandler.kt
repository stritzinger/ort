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

package org.ossreviewtoolkit.plugins.packagemanagers.hex

import org.cyclonedx.model.Component
import org.cyclonedx.model.ExternalReference

import org.ossreviewtoolkit.model.Hash
import org.ossreviewtoolkit.model.HashAlgorithm
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageLinkage
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.VcsType
import org.ossreviewtoolkit.model.utils.DependencyHandler

/**
 * A [DependencyHandler] for CycloneDX SBOM dependencies from Erlang/Elixir projects.
 *
 * This handler translates CycloneDX components into ORT's internal model, extracting
 * package metadata like licenses, URLs, and VCS information from the SBOM.
 */
internal class CycloneDxDependencyHandler : DependencyHandler<CycloneDxDependency> {
    private val dependencyMap = mutableMapOf<String, CycloneDxDependency>()

    /**
     * Set up the dependency map for resolving transitive dependencies.
     */
    fun setDependencies(dependencies: List<CycloneDxDependency>) {
        dependencyMap.clear()
        dependencies.associateByTo(dependencyMap) { it.bomRef }
    }

    override fun identifierFor(dependency: CycloneDxDependency): Identifier =
        Identifier(
            type = PACKAGE_TYPE,
            namespace = dependency.component.group.orEmpty(),
            name = dependency.component.name,
            version = dependency.component.version.orEmpty()
        )

    override fun dependenciesFor(dependency: CycloneDxDependency): List<CycloneDxDependency> =
        dependency.dependsOn.mapNotNull { bomRef -> dependencyMap[bomRef] }

    override fun linkageFor(dependency: CycloneDxDependency): PackageLinkage = PackageLinkage.DYNAMIC

    override fun createPackage(dependency: CycloneDxDependency, issues: MutableCollection<Issue>): Package {
        val component = dependency.component

        return Package(
            id = identifierFor(dependency),
            purl = component.purl.orEmpty(),
            declaredLicenses = extractLicenses(component),
            authors = extractAuthors(component),
            description = component.description.orEmpty(),
            homepageUrl = findExternalReferenceUrl(component, ExternalReference.Type.WEBSITE),
            binaryArtifact = RemoteArtifact.EMPTY,
            sourceArtifact = extractSourceArtifact(component),
            vcs = extractVcsInfo(component)
        )
    }

    /**
     * Extract declared licenses from a CycloneDX component.
     */
    private fun extractLicenses(component: Component): Set<String> {
        val licenses = mutableSetOf<String>()

        component.licenses?.licenses?.forEach { licenseChoice ->
            licenseChoice.id?.let { licenses += it }
                ?: licenseChoice.name?.let { licenses += it }
        }

        return licenses
    }

    /**
     * Extract authors from a CycloneDX component.
     */
    private fun extractAuthors(component: Component): Set<String> =
        component.author?.let { setOf(it) } ?: emptySet()

    /**
     * Extract VCS information from a CycloneDX component's external references.
     */
    private fun extractVcsInfo(component: Component): VcsInfo {
        val vcsUrl = findExternalReferenceUrl(component, ExternalReference.Type.VCS)
        if (vcsUrl.isEmpty()) return VcsInfo.EMPTY

        return VcsInfo(
            type = VcsType.GIT,
            url = vcsUrl,
            revision = "",
            path = ""
        )
    }

    /**
     * Extract source artifact from a CycloneDX component's external references.
     */
    private fun extractSourceArtifact(component: Component): RemoteArtifact {
        val distributionRef = component.externalReferences?.find {
            it.type == ExternalReference.Type.DISTRIBUTION
        } ?: return RemoteArtifact.EMPTY

        val url = distributionRef.url.orEmpty()
        if (url.isEmpty()) return RemoteArtifact.EMPTY

        val hash = distributionRef.hashes?.firstOrNull()?.let { cdxHash ->
            Hash(
                value = cdxHash.value,
                algorithm = mapHashAlgorithm(cdxHash.algorithm)
            )
        } ?: Hash.NONE

        return RemoteArtifact(url = url, hash = hash)
    }

    /**
     * Find the URL for a specific external reference type.
     */
    private fun findExternalReferenceUrl(component: Component, type: ExternalReference.Type): String =
        component.externalReferences?.find { it.type == type }?.url.orEmpty()

    /**
     * Map CycloneDX hash algorithm to ORT's HashAlgorithm.
     */
    private fun mapHashAlgorithm(cdxAlgorithm: String?): HashAlgorithm =
        when (cdxAlgorithm?.uppercase()) {
            "SHA-256", "SHA256" -> HashAlgorithm.SHA256
            "SHA-512", "SHA512" -> HashAlgorithm.SHA512
            "SHA-1", "SHA1" -> HashAlgorithm.SHA1
            "MD5" -> HashAlgorithm.MD5
            "SHA-384", "SHA384" -> HashAlgorithm.SHA384
            else -> HashAlgorithm.UNKNOWN
        }
}

