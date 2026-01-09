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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempfile
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

import org.ossreviewtoolkit.model.Severity

class CycloneDxSbomTest : StringSpec({
    "parse()" should {
        "parse a valid CycloneDX SBOM with dependencies" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "pkg:hex/my-app@1.0.0",
                      "dependsOn": ["pkg:hex/cowboy@2.9.0"]
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.bom.shouldNotBeNull()
            result.dependencies shouldHaveSize 1
            result.dependencies.first().component.name shouldBe "cowboy"
            result.dependencies.first().dependsOn shouldHaveSize 0
            result.rootRef shouldBe "pkg:hex/my-app@1.0.0"
            result.issues shouldHaveSize 0
        }

        "handle SBOM with no metadata component" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.bom.shouldNotBeNull()
            result.rootRef shouldBe null
            result.dependencies shouldHaveSize 1
        }

        "throw exception for invalid JSON" {
            val file = tempfile(suffix = ".json").apply {
                writeText("{ invalid json }")
            }

            shouldThrow<Exception> {
                CycloneDxSbom.parse(file, "Test")
            }
        }

        "handle components without bom-ref or purl" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "cowboy",
                      "version": "2.9.0"
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 0
            result.issues shouldHaveSize 1
            result.issues.first().message shouldBe "Dependency 'cowboy' has neither 'bom-ref' nor 'purl'; skipping it."
        }

        "normalize bom-ref and purl aliases" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "ref-1",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "ref-1",
                      "dependsOn": []
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 1
            result.dependencies.first().bomRef shouldBe "pkg:hex/cowboy@2.9.0"
        }

        "handle transitive dependencies" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/ranch@1.8.0",
                      "name": "ranch",
                      "version": "1.8.0",
                      "purl": "pkg:hex/ranch@1.8.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "pkg:hex/my-app@1.0.0",
                      "dependsOn": ["pkg:hex/cowboy@2.9.0"]
                    },
                    {
                      "ref": "pkg:hex/cowboy@2.9.0",
                      "dependsOn": ["pkg:hex/ranch@1.8.0"]
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 2
            val cowboy = result.dependencies.find { it.component.name == "cowboy" }
            cowboy.shouldNotBeNull()
            cowboy.dependsOn shouldHaveSize 1
            cowboy.dependsOn.first() shouldBe "pkg:hex/ranch@1.8.0"

            val ranch = result.dependencies.find { it.component.name == "ranch" }
            ranch.shouldNotBeNull()
            ranch.dependsOn shouldHaveSize 0
        }

        "create issues for missing dependencies in graph" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "pkg:hex/cowboy@2.9.0",
                      "dependsOn": ["pkg:hex/missing@1.0.0"]
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.issues shouldHaveSize 2
            val missingInGraphIssue = result.issues.find {
                it.message.contains("SBOM dependency graph contains") && it.severity == Severity.WARNING
            }

            missingInGraphIssue.shouldNotBeNull()

            val missingRefIssue = result.issues.find {
                it.message.contains("references missing ref") && it.message.contains("pkg:hex/missing@1.0.0")
            }

            missingRefIssue.shouldNotBeNull()
        }

        "handle component with only bom-ref (no purl)" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "ref-only",
                      "name": "cowboy",
                      "version": "2.9.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "ref-only",
                      "dependsOn": []
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 1
            result.dependencies.first().bomRef shouldBe "ref-only"
        }
    }

    "metadata()" should {
        "extract all metadata fields" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0",
                      "group": "com.example",
                      "description": "Test app",
                      "author": "Test Author",
                      "licenses": [
                        {
                          "id": "Apache-2.0"
                        }
                      ],
                      "externalReferences": [
                        {
                          "type": "vcs",
                          "url": "https://github.com/example/my-app"
                        },
                        {
                          "type": "website",
                          "url": "https://example.com"
                        }
                      ]
                    }
                  }
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata.shouldNotBeNull()
            metadata.name shouldBe "my-app"
            metadata.namespace shouldBe "com.example"
            metadata.version shouldBe "1.0.0"
            metadata.description shouldBe "Test app"
            metadata.authors shouldHaveSize 1
            metadata.declaredLicenses shouldHaveSize 1
            metadata.vcsUrl shouldBe "https://github.com/example/my-app"
            metadata.homepageUrl shouldBe "https://example.com"
        }

        "return null if metadata component is missing" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata shouldBe null
        }

        "extract metadata with license name instead of id" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0",
                      "licenses": [
                        {
                          "name": "MIT License"
                        }
                      ]
                    }
                  }
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata.shouldNotBeNull()
            metadata.declaredLicenses shouldHaveSize 1
            metadata.declaredLicenses.first() shouldBe "MIT License"
        }

        "extract metadata with multiple licenses" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0",
                      "licenses": [
                        {
                          "id": "Apache-2.0"
                        },
                        {
                          "id": "MIT"
                        },
                        {
                          "name": "Custom License"
                        }
                      ]
                    }
                  }
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata.shouldNotBeNull()
            metadata.declaredLicenses shouldHaveSize 3
            metadata.declaredLicenses shouldBe setOf("Apache-2.0", "MIT", "Custom License")
        }

        "extract metadata with no author" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  }
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata.shouldNotBeNull()
            metadata.authors shouldHaveSize 0
        }

        "extract metadata with no licenses" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  }
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val parseResult = CycloneDxSbom.parse(file, "Test")
            val metadata = CycloneDxSbom.projectMetadata(parseResult.bom!!)

            metadata.shouldNotBeNull()
            metadata.declaredLicenses shouldHaveSize 0
        }
    }

    "parse() edge cases" should {
        "handle circular dependencies" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/ranch@1.8.0",
                      "name": "ranch",
                      "version": "1.8.0",
                      "purl": "pkg:hex/ranch@1.8.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "pkg:hex/my-app@1.0.0",
                      "dependsOn": ["pkg:hex/cowboy@2.9.0"]
                    },
                    {
                      "ref": "pkg:hex/cowboy@2.9.0",
                      "dependsOn": ["pkg:hex/ranch@1.8.0"]
                    },
                    {
                      "ref": "pkg:hex/ranch@1.8.0",
                      "dependsOn": ["pkg:hex/cowboy@2.9.0"]
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 2
            val cowboy = result.dependencies.find { it.component.name == "cowboy" }
            cowboy.shouldNotBeNull()
            cowboy.dependsOn shouldHaveSize 1
            cowboy.dependsOn.first() shouldBe "pkg:hex/ranch@1.8.0"

            val ranch = result.dependencies.find { it.component.name == "ranch" }
            ranch.shouldNotBeNull()
            ranch.dependsOn shouldHaveSize 1
            ranch.dependsOn.first() shouldBe "pkg:hex/cowboy@2.9.0"
        }

        "handle empty components array" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": []
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 0
            result.issues shouldHaveSize 0
        }

        "handle empty dependencies array" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ],
                  "dependencies": []
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            result.dependencies shouldHaveSize 1
            result.dependencies.first().dependsOn shouldHaveSize 0
            result.rootRef shouldBe "pkg:hex/my-app@1.0.0"
        }

        "handle root component referencing missing dependencies" {
            val bomJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "pkg:hex/my-app@1.0.0",
                      "name": "my-app",
                      "version": "1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "pkg:hex/cowboy@2.9.0",
                      "name": "cowboy",
                      "version": "2.9.0",
                      "purl": "pkg:hex/cowboy@2.9.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "pkg:hex/my-app@1.0.0",
                      "dependsOn": ["pkg:hex/cowboy@2.9.0", "pkg:hex/missing@1.0.0"]
                    }
                  ]
                }
            """.trimIndent()

            val file = tempfile(suffix = ".json").apply {
                writeText(bomJson)
            }

            val result = CycloneDxSbom.parse(file, "Test")

            // The parser checks for missing refs in the dependency graph
            result.issues.any {
                it.message.contains("SBOM dependency graph contains") ||
                    it.message.contains("references missing ref")
            } shouldBe true
        }
    }
})
