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

package org.ossreviewtoolkit.utils.cyclonedx

import org.cyclonedx.model.Component
import org.cyclonedx.model.ExternalReference

import org.ossreviewtoolkit.downloader.VcsHost
import org.ossreviewtoolkit.model.Hash
import org.ossreviewtoolkit.model.HashAlgorithm
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageLinkage
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.utils.DependencyHandler
import org.ossreviewtoolkit.model.utils.PurlType
import org.ossreviewtoolkit.model.utils.parsePurl
import org.ossreviewtoolkit.model.utils.toOrtType

/**
 * A [DependencyHandler] for CycloneDX SBOM dependencies.
 */
class CycloneDxDependencyHandler : DependencyHandler<CycloneDxDependency> {

    private val dependencyMap = mutableMapOf<String, CycloneDxDependency>()

    fun indexDependencies(dependencies: List<CycloneDxDependency>) {
        dependencyMap.clear()
        dependencies.associateByTo(dependencyMap) { it.bomRef }
    }

    override fun identifierFor(dependency: CycloneDxDependency): Identifier {
        val component = dependency.component

        val parsedPurl = parsePurl(component.purl)

        val namespace = parsedPurl?.namespace?.takeIf { it.isNotBlank() }
            ?: component.group.orEmpty()

        val name = parsedPurl?.name?.takeIf { it.isNotBlank() }
            ?: component.name

        val version = parsedPurl?.version?.takeIf { it.isNotBlank() }
            ?: component.version.orEmpty()

        return Identifier(
            type = ortTypeFromPurl(component.purl) ?: DEFAULT_ORT_TYPE,
            namespace = namespace,
            name = name,
            version = version
        )
    }

    override fun dependenciesFor(dependency: CycloneDxDependency): List<CycloneDxDependency> =
        dependency.dependsOn.mapNotNull { dependencyMap[it] }

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
            vcs = extractVcs(component)
        )
    }

    private fun extractLicenses(component: Component): Set<String> =
        component.licenses?.licenses
            ?.mapNotNull { it.id ?: it.name }
            ?.toSet()
            ?: emptySet()

    /**
     * Prefer authors[] → manufacturer → legacy author.
     */
    private fun extractAuthors(component: Component): Set<String> {
        val authorsFromArray = component.authors.orEmpty()
            .mapNotNull { it.name ?: it.email }
            .filter { it.isNotBlank() }
            .toSet()

        if (authorsFromArray.isNotEmpty()) return authorsFromArray

        component.manufacturer?.name
            ?.takeIf { it.isNotBlank() }
            ?.let { return setOf(it) }

        return component.author
            ?.takeIf { it.isNotBlank() }
            ?.let { setOf(it) }
            ?: emptySet()
    }

    private fun extractVcs(component: Component): VcsInfo {
        val vcsUrl = findExternalReferenceUrl(
            component = component,
            type = ExternalReference.Type.VCS,
            preferVcsHostParseable = true
        )

        return if (vcsUrl.isBlank()) {
            VcsInfo.EMPTY
        } else {
            VcsHost.parseUrl(vcsUrl)
        }
    }

    /**
     * Extract source artifact using ExternalReference.Type.DISTRIBUTION only.
     */
    private fun extractSourceArtifact(component: Component): RemoteArtifact {
        val ref = component.externalReferences.orEmpty()
            .firstOrNull { it.type == ExternalReference.Type.DISTRIBUTION }
            ?: return RemoteArtifact.EMPTY

        val url = ref.url?.takeIf { it.isNotBlank() } ?: return RemoteArtifact.EMPTY

        val hash = ref.hashes
            ?.mapNotNull { cdxHash ->
                val algorithm = mapHashAlgorithm(cdxHash.algorithm)
                if (algorithm != HashAlgorithm.NONE && algorithm != HashAlgorithm.UNKNOWN) {
                    Hash(cdxHash.value, algorithm)
                } else {
                    null
                }
            }
            ?.maxByOrNull { it.algorithm.size }
            ?: Hash.NONE

        return RemoteArtifact(url = url, hash = hash)
    }

    /**
     * Find a stable external reference URL.
     *
     * - Uses only non-blank URLs
     * - For VCS, prefers URLs parseable by [VcsHost]
     */
    private fun findExternalReferenceUrl(
        component: Component,
        type: ExternalReference.Type,
        preferVcsHostParseable: Boolean = false
    ): String {
        val urls = component.externalReferences.orEmpty()
            .asSequence()
            .filter { it.type == type }
            .mapNotNull { it.url?.takeIf(String::isNotBlank) }
            .toList()

        if (urls.isEmpty()) return ""

        if (preferVcsHostParseable) {
            urls.firstOrNull { VcsHost.parseUrl(it) != VcsInfo.EMPTY }?.let { return it }
        }

        return urls.first()
    }

    private fun mapHashAlgorithm(cdxAlgorithm: String?): HashAlgorithm =
        if (cdxAlgorithm.isNullOrBlank()) {
            HashAlgorithm.NONE
        } else {
            HashAlgorithm.fromString(cdxAlgorithm)
        }

    private fun ortTypeFromPurl(purl: String?): String? {
        val parsed = parsePurl(purl) ?: return null
        val purlType = parsed.getPurlType() ?: PurlType.GENERIC
        return purlType.toOrtType()
    }

    companion object {
        private const val DEFAULT_ORT_TYPE = "CycloneDX"
    }
}
