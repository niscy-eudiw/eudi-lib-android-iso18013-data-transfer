/*
 * Copyright (c) 2023-2024 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.iso18013.transfer.internal

import android.content.Context
import android.os.Build
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor

internal val Any.TAG: String
    get() {
        if (this is String) return this
        val fullClassName: String = this::class.qualifiedName ?: this::class.java.typeName
        val outerClassName = fullClassName.substringBefore('$')
        val simplerOuterClassName = outerClassName.substringAfterLast('.')
        return if (simplerOuterClassName.isEmpty()) {
            fullClassName
        } else {
            simplerOuterClassName.removeSuffix("Kt")
        }
    }
internal fun Context.mainExecutor(): Executor {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        mainExecutor
    } else {
        ContextCompat.getMainExecutor(applicationContext)
    }
}
