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

import java.io.File

import org.cyclonedx.model.Bom

import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.analyzer.PackageManagerResult
import org.ossreviewtoolkit.downloader.VcsHost
import org.ossreviewtoolkit.downloader.VersionControlSystem
import org.ossreviewtoolkit.model.DependencyGraph
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.ProjectAnalyzerResult
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.utils.DependencyGraphBuilder
import org.ossreviewtoolkit.utils.cyclonedx.parser.CycloneDxSbom

/**
 * Base class for package managers that analyze CycloneDX SBOMs.
 *
 * This provides common functionality for parsing CycloneDX SBOMs and converting them
 * into ORT's internal data structures. Subclasses only need to specify the project type
 * and definition file patterns.
 */
abstract class CycloneDxPackageManager(
    projectType: String
) : PackageManager(projectType) {

    private val dependencyHandler = CycloneDxDependencyHandler()

    // Create a new graph builder for each resolution to avoid state leakage between tests
    private var graphBuilder: DependencyGraphBuilder<CycloneDxDependency>? = null

    override fun resolveDependencies(
        analysisRoot: File,
        definitionFile: File,
        excludes: Excludes,
        analyzerConfig: AnalyzerConfiguration,
        labels: Map<String, String>
    ): List<ProjectAnalyzerResult> {
        val issues = mutableListOf<Issue>()

        val parseResult = CycloneDxSbom.parse(definitionFile, projectType)
        issues += parseResult.issues

        val allDependencies = parseResult.dependencies
        val dependenciesByRef = parseResult.dependenciesByRef
        val rootRef = parseResult.rootRef

        dependencyHandler.indexDependencies(allDependencies)

        // Create a new graph builder for each resolution to avoid state leakage between tests
        graphBuilder = DependencyGraphBuilder(dependencyHandler)
        val builder = graphBuilder!!

        val project = createProjectFromSbom(definitionFile, parseResult.bom, issues)

        val validBomRefs = buildSet {
            addAll(allDependencies.map { it.bomRef })
            rootRef?.let { add(it) }
        }

        val directDependencyRefs: List<String> = when {
            rootRef != null -> {
                // Standard case: metadata.component is present and used as root.
                dependenciesByRef[rootRef].orEmpty()
            }

            dependenciesByRef.isNotEmpty() -> {
                // Heuristic: infer "root nodes" (nodes that are never depended-on) as direct dependencies.
                val nodes = dependenciesByRef.keys
                val incoming = dependenciesByRef.values.flatten().toSet()
                val rootNodes = (nodes - incoming).filter { it in validBomRefs }.sorted()

                if (rootNodes.isNotEmpty()) {
                    rootNodes
                } else {
                    emptyList()
                }
            }

            else -> emptyList()
        }

        // Validate rootRef's direct dependency references (when rootRef exists).
        if (rootRef != null) {
            directDependencyRefs.forEach { ref ->
                if (ref !in validBomRefs) {
                    issues += Issue(
                        source = projectType,
                        message = "Root component references missing ref '$ref' as a direct dependency."
                    )
                }
            }
        }

        val directDependencies = allDependencies.filter { it.bomRef in directDependencyRefs }

        val (requiredDeps, optionalDeps, excludedDeps) = directDependencies.partitionByScope()

        when {
            directDependencies.isNotEmpty() -> {
                if (requiredDeps.isNotEmpty()) {
                    builder.addDependencies(project.id, SCOPE_DEPENDENCIES, requiredDeps)
                }

                if (optionalDeps.isNotEmpty()) {
                    builder.addDependencies(project.id, SCOPE_OPTIONAL_DEPENDENCIES, optionalDeps)
                }

                if (excludedDeps.isNotEmpty()) {
                    builder.addDependencies(project.id, SCOPE_DEV_DEPENDENCIES, excludedDeps)
                }
            }

            allDependencies.isNotEmpty() -> {
                issues += Issue(
                    source = projectType,
                    message = "Could not determine direct dependencies from SBOM dependency graph. " +
                        "Treating all components as direct dependencies.",
                    severity = Severity.WARNING
                )
                builder.addDependencies(project.id, SCOPE_DEPENDENCIES, allDependencies)
            }
        }

        // Populate ProjectAnalyzerResult.packages (some consumers expect this to be non-empty).
        val discoveredPackages = builder.packages()

        return listOf(
            ProjectAnalyzerResult(
                project = project.copy(scopeNames = builder.scopesFor(project.id)),
                packages = discoveredPackages,
                issues = issues
            )
        )
    }

    override fun createPackageManagerResult(projectResults: Map<File, List<ProjectAnalyzerResult>>) =
        PackageManagerResult(
            projectResults,
            graphBuilder?.build() ?: DependencyGraph(),
            graphBuilder?.packages() ?: emptySet()
        )

    /**
     * Create a Project from the CycloneDX metadata component.
     */
    protected fun createProjectFromSbom(definitionFile: File, bom: Bom, issues: MutableList<Issue>): Project {
        val projectMetadata = CycloneDxSbom.projectMetadata(bom)

        val projectId = if (projectMetadata != null) {
            val projectName = projectMetadata.name
            if (projectName.isBlank()) {
                issues += Issue(
                    source = projectType,
                    message = "CycloneDX SBOM metadata.component does not contain a 'name'. " +
                        "Using fallback project name from directory.",
                    severity = Severity.WARNING
                )
            }

            Identifier(
                type = projectType,
                namespace = projectMetadata.namespace,
                name = projectName.takeIf { it.isNotBlank() } ?: definitionFile.parentFile.name,
                version = projectMetadata.version
            )
        } else {
            issues += Issue(
                source = projectType,
                message = "CycloneDX SBOM does not contain metadata.component. " +
                    "Using fallback project identification.",
                severity = Severity.WARNING
            )
            Identifier(
                type = projectType,
                namespace = "",
                name = definitionFile.parentFile.name,
                version = ""
            )
        }

        val vcs = if (projectMetadata?.vcsUrl?.isNotEmpty() == true) {
            VcsHost.parseUrl(projectMetadata.vcsUrl)
        } else {
            VcsInfo.EMPTY
        }

        return Project(
            id = projectId,
            definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path,
            authors = projectMetadata?.authors ?: emptySet(),
            declaredLicenses = projectMetadata?.declaredLicenses ?: emptySet(),
            vcs = vcs,
            vcsProcessed = processProjectVcs(definitionFile.parentFile, vcs),
            homepageUrl = projectMetadata?.homepageUrl.orEmpty(),
            scopeNames = emptySet(),
            description = projectMetadata?.description.orEmpty()
        )
    }

    /**
     * Create a fallback project when SBOM parsing fails.
     */
    protected fun createFallbackProject(definitionFile: File): Project {
        val fallbackName = definitionFile.parentFile.name
        if (fallbackName.isBlank()) {
            return Project(
                id = Identifier(
                    type = projectType,
                    namespace = "",
                    name = definitionFile.nameWithoutExtension,
                    version = ""
                ),
                definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path,
                authors = emptySet(),
                declaredLicenses = emptySet(),
                vcs = VcsInfo.EMPTY,
                vcsProcessed = processProjectVcs(definitionFile.parentFile),
                homepageUrl = "",
                scopeNames = emptySet()
            )
        }

        return Project(
            id = Identifier(
                type = projectType,
                namespace = "",
                name = fallbackName,
                version = ""
            ),
            definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path,
            authors = emptySet(),
            declaredLicenses = emptySet(),
            vcs = VcsInfo.EMPTY,
            vcsProcessed = processProjectVcs(definitionFile.parentFile),
            homepageUrl = "",
            scopeNames = emptySet()
        )
    }

    /**
     * Partition dependencies by their CycloneDX scope.
     *
     * According to CycloneDX spec:
     * - "required" (default): Component is required for runtime
     * - "optional": Component is optional at runtime
     * - "excluded": Component is for test/development, not reachable at runtime
     */
    private fun List<CycloneDxDependency>.partitionByScope():
        Triple<List<CycloneDxDependency>, List<CycloneDxDependency>, List<CycloneDxDependency>> {
        val required = mutableListOf<CycloneDxDependency>()
        val optional = mutableListOf<CycloneDxDependency>()
        val excluded = mutableListOf<CycloneDxDependency>()

        forEach { dep ->
            when (dep.component.scope?.name?.lowercase()) {
                "optional" -> optional.add(dep)
                "excluded" -> excluded.add(dep)
                else -> required.add(dep) // "required" or null (defaults to required per spec)
            }
        }

        return Triple(required, optional, excluded)
    }

    companion object {
        protected const val SCOPE_DEPENDENCIES = "dependencies"
        protected const val SCOPE_DEV_DEPENDENCIES = "devDependencies"
        protected const val SCOPE_OPTIONAL_DEPENDENCIES = "optionalDependencies"
    }
}
