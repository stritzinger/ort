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

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

import org.cyclonedx.model.Component
import org.cyclonedx.model.ExternalReference
import org.cyclonedx.model.Hash
import org.cyclonedx.model.License
import org.cyclonedx.model.LicenseChoice

import org.ossreviewtoolkit.model.HashAlgorithm
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.VcsInfo

class CycloneDxDependencyHandlerTest : StringSpec({
    val handler = CycloneDxDependencyHandler()

    "identifierFor()" should {
        "extract identifier from component with PURL" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                group = ""
                purl = "pkg:hex/cowboy@2.9.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            val identifier = handler.identifierFor(dependency)

            identifier.type shouldBe "hex"
            identifier.name shouldBe "cowboy"
            identifier.version shouldBe "2.9.0"
        }

        "use default type when PURL is missing" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                group = ""
                purl = null
            }

            val dependency = CycloneDxDependency(component, "ref-1", emptyList())

            val identifier = handler.identifierFor(dependency)

            identifier.type shouldBe "CycloneDX"
            identifier.name shouldBe "cowboy"
            identifier.version shouldBe "2.9.0"
        }

        "extract identifier with namespace/group" {
            val component = Component().apply {
                name = "phoenix"
                version = "1.7.0"
                group = "phoenixframework"
                purl = "pkg:hex/phoenix@1.7.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/phoenix@1.7.0", emptyList())

            val identifier = handler.identifierFor(dependency)

            identifier.type shouldBe "hex"
            identifier.namespace shouldBe "phoenixframework"
            identifier.name shouldBe "phoenix"
            identifier.version shouldBe "1.7.0"
        }

        "handle different PURL types" {
            val testCases = listOf(
                Triple("pkg:hex/cowboy@2.9.0", "hex", "cowboy"),
                Triple("pkg:hex/phoenix@1.7.0", "hex", "phoenix"),
                Triple("pkg:hex/ecto@3.10.0", "hex", "ecto"),
                Triple("pkg:otp/ssl@10.2", "otp", "ssl"),
                Triple("pkg:otp/crypto@5.1.2", "otp", "crypto")
            )

            testCases.forEach { (purl, expectedType, expectedName) ->
                val component = Component().apply {
                    name = expectedName
                    version = "1.0.0"
                    group = ""
                    this.purl = purl
                }

                val dependency = CycloneDxDependency(component, purl, emptyList())
                val identifier = handler.identifierFor(dependency)

                identifier.type shouldBe expectedType
                identifier.name shouldBe expectedName
            }
        }

        "handle unknown PURL types" {
            val component = Component().apply {
                name = "custom_package"
                version = "1.0.0"
                group = ""
                purl = "pkg:unknown/custom_package@1.0.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:unknown/custom_package@1.0.0", emptyList())

            val identifier = handler.identifierFor(dependency)

            identifier.type shouldBe "generic"
            identifier.name shouldBe "custom_package"

            val issues = mutableListOf<org.ossreviewtoolkit.model.Issue>()
            val pkg = handler.createPackage(dependency, issues)

            pkg.id.type shouldBe "generic"
        }
    }

    "createPackage()" should {
        "extract all package fields" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                group = ""
                purl = "pkg:hex/cowboy@2.9.0"
                description = "Small, fast, modern HTTP server"
                author = "Loïc Hoguin"
                licenses = LicenseChoice().apply {
                    licenses = listOf(
                        License().apply {
                            id = "ISC"
                        }
                    )
                }

                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.VCS
                        url = "https://github.com/ninenines/cowboy"
                    },
                    ExternalReference().apply {
                        type = ExternalReference.Type.WEBSITE
                        url = "https://ninenines.eu/docs/en/cowboy/2.9/guide/"
                    },
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            )
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.id.name shouldBe "cowboy"
            pkg.purl shouldBe "pkg:hex/cowboy@2.9.0"
            pkg.declaredLicenses shouldHaveSize 1
            pkg.declaredLicenses.first() shouldBe "ISC"
            pkg.authors shouldHaveSize 1
            pkg.authors.first() shouldBe "Loïc Hoguin"
            pkg.description shouldBe "Small, fast, modern HTTP server"
            pkg.homepageUrl shouldBe "https://ninenines.eu/docs/en/cowboy/2.9/guide/"
            pkg.vcs.type shouldBe org.ossreviewtoolkit.model.VcsType.GIT
            pkg.sourceArtifact.url shouldBe "https://hex.pm/packages/cowboy/2.9.0"
            pkg.sourceArtifact.hash.algorithm shouldBe HashAlgorithm.SHA256
        }

        "handle component with no external references" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.vcs shouldBe VcsInfo.EMPTY
            pkg.sourceArtifact shouldBe RemoteArtifact.EMPTY
            pkg.homepageUrl shouldBe ""
        }

        "prefer stronger hash algorithm when multiple are available" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(Hash.Algorithm.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            ),
                            Hash(
                                Hash.Algorithm.SHA_512,
                                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                            )
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.sourceArtifact.hash.algorithm shouldBe HashAlgorithm.SHA512
            pkg.sourceArtifact.hash.value shouldBe (
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                )
        }

        "extract license with name instead of id" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                licenses = LicenseChoice().apply {
                    licenses = listOf(
                        License().apply {
                            name = "ISC License"
                        }
                    )
                }
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.declaredLicenses shouldHaveSize 1
            pkg.declaredLicenses.first() shouldBe "ISC License"
        }

        "extract multiple licenses" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                licenses = LicenseChoice().apply {
                    licenses = listOf(
                        License().apply {
                            id = "Apache-2.0"
                        },
                        License().apply {
                            id = "MIT"
                        },
                        License().apply {
                            name = "Custom License"
                        }
                    )
                }
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.declaredLicenses shouldHaveSize 3
            pkg.declaredLicenses shouldBe setOf("Apache-2.0", "MIT", "Custom License")
        }

        "handle component with no licenses" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                licenses = null
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.declaredLicenses shouldHaveSize 0
        }

        "handle component with no author" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                author = null
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.authors shouldHaveSize 0
        }

        "verify linkageFor always returns DYNAMIC" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            handler.linkageFor(dependency) shouldBe org.ossreviewtoolkit.model.PackageLinkage.DYNAMIC
        }
    }

    "dependenciesFor()" should {
        "return empty list when no dependencies" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())

            handler.dependenciesFor(dependency) shouldHaveSize 0
        }

        "return dependencies when set" {
            val component1 = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
            }

            val component2 = Component().apply {
                name = "ranch"
                version = "1.8.0"
                purl = "pkg:hex/ranch@1.8.0"
            }

            val dep1 = CycloneDxDependency(component1, "pkg:hex/cowboy@2.9.0", listOf("pkg:hex/ranch@1.8.0"))
            val dep2 = CycloneDxDependency(component2, "pkg:hex/ranch@1.8.0", emptyList())

            handler.indexDependencies(listOf(dep1, dep2))

            val deps = handler.dependenciesFor(dep1)
            deps shouldHaveSize 1
            deps.first().component.name shouldBe "ranch"
        }
    }

    "extractSourceArtifact()" should {
        "handle distribution ref with no URL" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = ""
                        hashes = listOf(
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            )
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.sourceArtifact shouldBe RemoteArtifact.EMPTY
        }

        "handle distribution ref with URL but no hash" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = null
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.sourceArtifact.url shouldBe "https://hex.pm/packages/cowboy/2.9.0"
            pkg.sourceArtifact.hash shouldBe org.ossreviewtoolkit.model.Hash.NONE
        }

        "use first distribution ref when multiple exist" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            )
                        )
                    },
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://alternative.url/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            )
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.sourceArtifact.url shouldBe "https://hex.pm/packages/cowboy/2.9.0"
        }

        "handle unknown hash algorithm" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(
                                Hash.Algorithm.SHA_256,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            ),
                            // Simulate unknown algorithm by using a valid hash but we'll test the mapping
                            Hash(Hash.Algorithm.MD5, "d41d8cd98f00b204e9800998ecf8427e")
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            // Should prefer SHA_256 over MD5
            pkg.sourceArtifact.hash.algorithm shouldBe HashAlgorithm.SHA256
        }

        "handle only weak hash algorithm (MD5)" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.DISTRIBUTION
                        url = "https://hex.pm/packages/cowboy/2.9.0"
                        hashes = listOf(
                            Hash(Hash.Algorithm.MD5, "d41d8cd98f00b204e9800998ecf8427e")
                        )
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.sourceArtifact.hash.algorithm shouldBe HashAlgorithm.MD5
            pkg.sourceArtifact.hash.value shouldBe "d41d8cd98f00b204e9800998ecf8427e"
        }
    }

    "extractVcs()" should {
        "handle different VCS types" {
            val testCases = listOf(
                Pair("https://github.com/ninenines/cowboy", org.ossreviewtoolkit.model.VcsType.GIT),
                Pair("https://svn.example.com/repo/trunk", org.ossreviewtoolkit.model.VcsType.SUBVERSION)
            )

            testCases.forEach { (url, expectedType) ->
                val component = Component().apply {
                    name = "cowboy"
                    version = "2.9.0"
                    purl = "pkg:hex/cowboy@2.9.0"
                    externalReferences = listOf(
                        ExternalReference().apply {
                            type = ExternalReference.Type.VCS
                            this.url = url
                        }
                    )
                }

                val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
                val pkg = handler.createPackage(dependency, mutableListOf())

                pkg.vcs.type shouldBe expectedType
            }
        }

        "handle unknown VCS types gracefully" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.VCS
                        this.url = "https://hg.example.com/repo"
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            // Unknown VCS types should preserve the URL but have empty type
            pkg.vcs.url shouldBe "https://hg.example.com/repo"
            pkg.vcs.type shouldBe org.ossreviewtoolkit.model.VcsType.UNKNOWN
        }

        "handle invalid VCS URL gracefully" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.VCS
                        url = "not-a-valid-url"
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            // VcsHost.parseUrl should handle invalid URLs gracefully
            pkg.vcs.url shouldBe "not-a-valid-url"
        }

        "handle empty VCS URL" {
            val component = Component().apply {
                name = "cowboy"
                version = "2.9.0"
                purl = "pkg:hex/cowboy@2.9.0"
                externalReferences = listOf(
                    ExternalReference().apply {
                        type = ExternalReference.Type.VCS
                        url = ""
                    }
                )
            }

            val dependency = CycloneDxDependency(component, "pkg:hex/cowboy@2.9.0", emptyList())
            val pkg = handler.createPackage(dependency, mutableListOf())

            pkg.vcs shouldBe VcsInfo.EMPTY
        }
    }
})
