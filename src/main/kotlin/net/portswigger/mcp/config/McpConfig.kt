package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.Preferences
import java.lang.ref.WeakReference
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

class McpConfig(storage: Preferences, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(true)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(false)
    var requireHistoryAccessApproval by storage.boolean(false)

    // Database configuration
    var trafficLoggingEnabled by storage.boolean(true)
    var databasePath by storage.string("")  // Empty = use default in Burp project dir
    var logProxyTraffic by storage.boolean(true)
    var logRepeaterTraffic by storage.boolean(true)
    var logScannerTraffic by storage.boolean(true)
    var logIntruderTraffic by storage.boolean(true)
    var logExtensionTraffic by storage.boolean(true)

    // Raw socket tools (dangerous; intended for lab environments)
    var rawSocketToolsEnabled by storage.boolean(false)

    private var _alwaysAllowHttpHistory by storage.boolean(true)
    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) {
            if (_alwaysAllowHttpHistory != value) {
                _alwaysAllowHttpHistory = value
                notifyHistoryAccessChanged()
            }
        }

    private var _alwaysAllowWebSocketHistory by storage.boolean(true)
    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) {
            if (_alwaysAllowWebSocketHistory != value) {
                _alwaysAllowWebSocketHistory = value
                notifyHistoryAccessChanged()
            }
        }

    private var _autoApproveTargets by storage.stringList("")
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val historyAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    // Separate allowlist for raw socket tooling
    private var _rawSocketAllowedTargets by storage.stringList(
        "*.web-security-academy.net,*.h1-web-security-academy.net,*.exploit-server.net,*.oastify.com"
    )
    private val rawSocketTargetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            if (_autoApproveTargets != value) {
                _autoApproveTargets = value
                notifyTargetsChanged()
            }
        }

    var rawSocketAllowedTargets: String
        get() = _rawSocketAllowedTargets
        set(value) {
            if (_rawSocketAllowedTargets != value) {
                _rawSocketAllowedTargets = value
                notifyRawSocketTargetsChanged()
            }
        }

    fun addAutoApproveTarget(target: String): Boolean {
        val currentTargets = getAutoApproveTargetsList()
        if (target.trim().isNotEmpty() && !currentTargets.contains(target.trim())) {
            val newTargets = currentTargets + target.trim()
            autoApproveTargets = newTargets.joinToString(",")
            return true
        }
        return false
    }

    fun removeAutoApproveTarget(target: String): Boolean {
        val currentTargets = getAutoApproveTargetsList()
        val newTargets = currentTargets.filter { it != target.trim() }
        if (newTargets.size != currentTargets.size) {
            autoApproveTargets = newTargets.joinToString(",")
            return true
        }
        return false
    }

    fun getAutoApproveTargetsList(): List<String> {
        return if (_autoApproveTargets.isBlank()) {
            emptyList()
        } else {
            _autoApproveTargets.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun getRawSocketAllowedTargetsList(): List<String> {
        return if (_rawSocketAllowedTargets.isBlank()) {
            emptyList()
        } else {
            _rawSocketAllowedTargets.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun addRawSocketAllowedTarget(target: String): Boolean {
        val currentTargets = getRawSocketAllowedTargetsList()
        if (target.trim().isNotEmpty() && !currentTargets.contains(target.trim())) {
            val newTargets = currentTargets + target.trim()
            rawSocketAllowedTargets = newTargets.joinToString(",")
            return true
        }
        return false
    }

    fun removeRawSocketAllowedTarget(target: String): Boolean {
        val currentTargets = getRawSocketAllowedTargetsList()
        val newTargets = currentTargets.filter { it != target.trim() }
        if (newTargets.size != currentTargets.size) {
            rawSocketAllowedTargets = newTargets.joinToString(",")
            return true
        }
        return false
    }

    fun clearRawSocketAllowedTargets() {
        rawSocketAllowedTargets = ""
    }

    fun clearAutoApproveTargets() {
        autoApproveTargets = ""
    }

    fun addTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        targetsChangeListeners.add(registration)
        return ListenerHandle { removeTargetsChangeListener(registration) }
    }

    private fun removeTargetsChangeListener(registration: ListenerRegistration) {
        targetsChangeListeners.remove(registration)
    }

    private fun notifyTargetsChanged() {
        cleanupStaleListeners(targetsChangeListeners)
        val listeners = targetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Targets change listener failed: ${e.message}")
            }
        }
    }

    fun addRawSocketTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        rawSocketTargetsChangeListeners.add(registration)
        return ListenerHandle { removeRawSocketTargetsChangeListener(registration) }
    }

    private fun removeRawSocketTargetsChangeListener(registration: ListenerRegistration) {
        rawSocketTargetsChangeListeners.remove(registration)
    }

    private fun notifyRawSocketTargetsChanged() {
        cleanupStaleListeners(rawSocketTargetsChangeListeners)
        val listeners = rawSocketTargetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Raw socket targets change listener failed: ${e.message}")
            }
        }
    }

    fun addHistoryAccessChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        historyAccessChangeListeners.add(registration)
        return ListenerHandle { removeHistoryAccessChangeListener(registration) }
    }

    private fun removeHistoryAccessChangeListener(registration: ListenerRegistration) {
        historyAccessChangeListeners.remove(registration)
    }

    private fun notifyHistoryAccessChanged() {
        cleanupStaleListeners(historyAccessChangeListeners)
        val listeners = historyAccessChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("History access change listener failed: ${e.message}")
            }
        }
    }

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        historyAccessChangeListeners.clear()
        rawSocketTargetsChangeListeners.clear()
    }
}

fun Preferences.boolean(default: Boolean = false) =
    PreferencesDelegate(getter = { key -> getBoolean(key) ?: default }, setter = { key, value -> setBoolean(key, value) })

fun Preferences.string(default: String) =
    PreferencesDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun Preferences.int(default: Int) =
    PreferencesDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

fun Preferences.stringList(default: String) =
    PreferencesDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

class PreferencesDelegate<T>(
    private val getter: (name: String) -> T, private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}

class ListenerRegistration(listener: () -> Unit) {
    val listener: WeakReference<() -> Unit> = WeakReference(listener)
}

fun interface ListenerHandle {
    fun remove()
}
