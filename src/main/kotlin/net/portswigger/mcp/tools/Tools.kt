package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.Component
import java.awt.Container
import java.awt.EventQueue
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {
    val disabledSet = config.getDisabledToolsList()
    fun enabled(name: String) = name !in disabledSet

    if (enabled("send_http1_request")) mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    if (enabled("send_http2_request")) mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    if (enabled("create_repeater_tab")) mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    if (enabled("send_to_intruder")) mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    if (enabled("url_encode")) mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    if (enabled("url_decode")) mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    if (enabled("base64_encode")) mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    if (enabled("base64_decode")) mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    if (enabled("generate_random_string")) mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    if (enabled("output_project_options")) mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    if (enabled("output_user_options")) mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    if (enabled("set_project_options")) mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    if (enabled("set_user_options")) mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        if (enabled("get_scanner_issues")) mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        if (enabled("generate_collaborator_payload")) mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        if (enabled("get_collaborator_interactions")) mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }

        if (enabled("start_active_scan")) mcpTool<StartActiveScan>(
            "Starts an active vulnerability scan on the given HTTP request using the Burp Scanner. " +
            "Sends the request first to capture a baseline response, then passes it to the scanner. " +
            "Use get_scanner_issues to poll for discovered vulnerabilities. Pro only."
        ) {
            api.logging().logToOutput("MCP starting active scan (crawl): $targetHostname:$targetPort")
            val scheme = if (usesHttps) "https" else "http"
            val portSuffix = if ((usesHttps && targetPort == 443) || (!usesHttps && targetPort == 80)) "" else ":$targetPort"
            val targetUrl = "$scheme://$targetHostname$portSuffix/"
            api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(targetUrl))
            "Active crawl+audit started for $targetUrl. Use get_scanner_issues to poll for results."
        }

        if (enabled("start_passive_scan")) mcpTool<StartPassiveScan>(
            "Runs passive vulnerability checks on the given HTTP request without sending additional requests. " +
            "Sends the request once to obtain a response, then runs Burp passive scan checks on the pair. " +
            "Passive checks detect issues like missing security headers, information disclosure, and insecure cookies. " +
            "Use get_scanner_issues to view results. Pro only."
        ) {
            api.logging().logToOutput("MCP adding to sitemap for passive analysis: $targetHostname:$targetPort")
            val fixedContent = content.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
            val requestResponse = api.http().sendRequest(request)
            api.siteMap().add(requestResponse)
            "Request added to sitemap for $targetHostname:$targetPort. " +
            "Burp's passive scanner will automatically analyse it. Use get_scanner_issues to view results."
        }
    }

    if (enabled("get_proxy_http_history")) mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_http_history_regex")) mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_websocket_history")) mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_websocket_history_regex")) mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // -------------------------------------------------------------------------
    // History by index
    // -------------------------------------------------------------------------

    if (enabled("get_proxy_http_history_item")) mcpTool<GetProxyHttpHistoryItem>(
        "Returns a single proxy HTTP history entry by its zero-based index. " +
        "Use get_proxy_http_history to discover valid indices."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val history = api.proxy().history()
        if (index < 0 || index >= history.size) {
            return@mcpTool "Index $index is out of range. History contains ${history.size} item(s)."
        }
        truncateIfNeeded(Json.encodeToString(history[index].toSerializableForm()))
    }

    // -------------------------------------------------------------------------
    // Scope
    // -------------------------------------------------------------------------

    if (enabled("is_in_scope")) mcpTool<IsInScope>("Checks whether a URL is within the Burp Suite target scope.") {
        val inScope = api.scope().isInScope(url)
        if (inScope) "In scope: $url" else "NOT in scope: $url"
    }

    if (enabled("add_to_scope")) mcpTool<AddToScope>("Adds a URL to the Burp Suite target scope.") {
        api.scope().includeInScope(url)
        "Added to scope: $url"
    }

    if (enabled("remove_from_scope")) mcpTool<RemoveFromScope>("Removes a URL from the Burp Suite target scope.") {
        api.scope().excludeFromScope(url)
        "Removed from scope: $url"
    }

    // -------------------------------------------------------------------------
    // Site map
    // -------------------------------------------------------------------------

    if (enabled("get_site_map")) mcpPaginatedTool<GetSiteMap>("Returns paginated entries from the Burp Suite target sitemap.") {
        api.siteMap().requestResponses().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_site_map_for_url")) mcpPaginatedTool<GetSiteMapForUrl>(
        "Returns paginated sitemap entries whose URL starts with the given prefix. " +
        "Useful for drilling into a specific host or path."
    ) {
        api.siteMap().requestResponses(SiteMapFilter.prefixFilter(url)).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("set_task_execution_engine_state")) mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    if (enabled("set_proxy_intercept_state")) mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    // -------------------------------------------------------------------------
    // Response extraction
    // -------------------------------------------------------------------------

    if (enabled("extract_from_response")) mcpTool<ExtractFromResponse>(
        "Extracts all regex matches from an HTTP response string. " +
        "Use 'group' to select a specific capture group (0 = entire match, 1+ = numbered group). " +
        "Useful for pulling out CSRF tokens, auth values, redirect URLs, or any pattern from a response. " +
        "The response can come from send_http1_request, send_http2_request, or any history tool."
    ) {
        val compiled = try {
            Pattern.compile(regex, Pattern.DOTALL)
        } catch (e: Exception) {
            return@mcpTool "Invalid regex: ${e.message}"
        }

        val matcher = compiled.matcher(response)
        val results = mutableListOf<String>()

        while (matcher.find()) {
            if (group > matcher.groupCount()) {
                return@mcpTool "Group $group does not exist — the regex has ${matcher.groupCount()} capture group(s)."
            }
            results.add(matcher.group(group) ?: "")
        }

        if (results.isEmpty()) "No matches found" else results.joinToString("\n")
    }

    // -------------------------------------------------------------------------
    // Proxy history search
    // -------------------------------------------------------------------------

    if (enabled("search_proxy_history")) mcpPaginatedTool<SearchProxyHistory>(
        "Searches proxy HTTP history with optional filters combined with AND logic. " +
        "statusCode: exact HTTP status code (200, 302, 401, …). " +
        "method: HTTP verb, case-insensitive (GET, POST, PUT, …). " +
        "contentType: substring match on the Content-Type response header (json, html, xml, …). " +
        "bodyKeyword: case-insensitive substring search in the response body only. " +
        "Omit any filter to match all values for that field."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history search")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")

        api.proxy().history().asSequence().filter { item ->
            val reqStr = item.request().toString()
            val respStr = item.response()?.toString() ?: ""

            // Method: first token of the request line ("GET / HTTP/1.1" → "GET")
            if (method != null) {
                val parsedMethod = reqStr.trimStart().split(" ", "\t").firstOrNull() ?: ""
                if (!parsedMethod.equals(method, ignoreCase = true)) return@filter false
            }

            // Status code: second token of the response status line ("HTTP/1.1 200 OK" → 200)
            if (statusCode != null) {
                val parsedStatus = respStr.lines().firstOrNull()
                    ?.split(" ")?.getOrNull(1)?.toIntOrNull()
                if (parsedStatus != statusCode) return@filter false
            }

            // Content-Type: header section only (before the blank line)
            if (contentType != null) {
                val sepIdx = respStr.indexOf("\r\n\r\n")
                val headerSection = if (sepIdx >= 0) respStr.substring(0, sepIdx) else respStr
                val hasMatch = headerSection.lines().any { line ->
                    line.startsWith("Content-Type:", ignoreCase = true) &&
                    line.contains(contentType, ignoreCase = true)
                }
                if (!hasMatch) return@filter false
            }

            // Body keyword: response body only (after the blank line)
            if (bodyKeyword != null) {
                val sepIdx = respStr.indexOf("\r\n\r\n")
                val body = if (sepIdx >= 0) respStr.substring(sepIdx + 4) else ""
                if (!body.contains(bodyKeyword, ignoreCase = true)) return@filter false
            }

            true
        }.map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // -------------------------------------------------------------------------
    // Repeater tabs
    // -------------------------------------------------------------------------

    if (enabled("list_repeater_tabs")) mcpTool("list_repeater_tabs", "Lists all tabs currently open in Burp Suite's Repeater. Returns each tab's zero-based index and display name so you can reference them by index in other Repeater tools.") {
        val tabs = repeaterTabs(api)
        if (tabs.isEmpty()) {
            "No Repeater tabs found. Make sure Burp's Repeater tab has been opened at least once."
        } else {
            tabs.joinToString("\n") { (index, name) -> "Index $index: $name" }
        }
    }

    if (enabled("get_repeater_tab_request")) mcpTool<GetRepeaterTabRequest>(
        "Returns the raw HTTP request loaded in the specified Repeater tab together with the resolved target host, port, and HTTPS flag. " +
        "Use list_repeater_tabs first to discover valid tab indices."
    ) {
        repeaterTabDetails(tabIndex, api)
            ?: "Could not read Repeater tab $tabIndex. Verify the index is valid and the tab contains a request."
    }

    if (enabled("send_repeater_tab_request")) mcpTool<SendRepeaterTabRequest>(
        "Sends the HTTP request from the specified Repeater tab through Burp's HTTP engine and returns the full response. " +
        "The target host, port, and scheme are auto-detected from the Repeater tab's target field. " +
        "Use list_repeater_tabs first to discover valid tab indices."
    ) {
        val info = repeaterTabConnectionInfo(tabIndex, api)
            ?: return@mcpTool "Could not read Repeater tab $tabIndex. Verify the index is valid and the tab has a request with a Host header."

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(info.hostname, info.port, config, info.request, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP Repeater tab $tabIndex request denied: ${info.hostname}:${info.port}")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP sending Repeater tab $tabIndex: ${info.hostname}:${info.port}")
        val fixedRequest = info.request.replace("\r", "").replace("\n", "\r\n")
        val httpRequest = HttpRequest.httpRequest(HttpService.httpService(info.hostname, info.port, info.usesHttps), fixedRequest)
        val response = api.http().sendRequest(httpRequest)
        response?.toString() ?: "<no response>"
    }

    if (enabled("get_active_editor_contents")) mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    if (enabled("set_active_editor_contents")) mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class StartActiveScan(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetProxyHttpHistoryItem(val index: Int)

@Serializable
data class IsInScope(val url: String)

@Serializable
data class AddToScope(val url: String)

@Serializable
data class RemoveFromScope(val url: String)

@Serializable
data class GetSiteMap(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetSiteMapForUrl(
    val url: String,
    override val count: Int,
    override val offset: Int
) : Paginated

@Serializable
data class StartPassiveScan(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetRepeaterTabRequest(val tabIndex: Int)

@Serializable
data class SendRepeaterTabRequest(val tabIndex: Int)

@Serializable
data class ExtractFromResponse(
    val response: String,
    val regex: String,
    val group: Int = 0
)

@Serializable
data class SearchProxyHistory(
    val statusCode: Int? = null,
    val method: String? = null,
    val contentType: String? = null,
    val bodyKeyword: String? = null,
    override val count: Int,
    override val offset: Int
) : Paginated

// ---------------------------------------------------------------------------
// Repeater Swing utilities
// ---------------------------------------------------------------------------

private data class RepeaterConnectionInfo(
    val request: String,
    val hostname: String,
    val port: Int,
    val usesHttps: Boolean
)

private fun repeaterTabs(api: MontoyaApi): List<Pair<Int, String>> {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val result = mutableListOf<Pair<Int, String>>()
    runOnEdt {
        val pane = findRepeaterInnerTabbedPane(frame) ?: return@runOnEdt
        for (i in 0 until pane.tabCount) {
            val name = pane.getTitleAt(i)
            if (!name.isNullOrBlank() && name != "+") result.add(i to name)
        }
    }
    return result
}

private fun repeaterTabDetails(tabIndex: Int, api: MontoyaApi): String? {
    val info = repeaterTabConnectionInfo(tabIndex, api) ?: return null
    return buildString {
        appendLine("Target: ${if (info.usesHttps) "https" else "http"}://${info.hostname}:${info.port}")
        appendLine("HTTPS: ${info.usesHttps}")
        appendLine()
        append(info.request)
    }
}

private fun repeaterTabConnectionInfo(tabIndex: Int, api: MontoyaApi): RepeaterConnectionInfo? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    var result: RepeaterConnectionInfo? = null
    runOnEdt {
        val pane = findRepeaterInnerTabbedPane(frame) ?: return@runOnEdt
        if (tabIndex < 0 || tabIndex >= pane.tabCount) return@runOnEdt
        val tabComp = pane.getComponentAt(tabIndex) as? Container ?: return@runOnEdt
        val requestText = findRepeaterRequestText(tabComp) ?: return@runOnEdt
        val targetUrl = findRepeaterTargetUrl(tabComp)
        val (hostname, port, https) = if (targetUrl != null) {
            parseRepeaterTargetUrl(targetUrl) ?: deriveTargetFromHostHeader(requestText)
        } else {
            deriveTargetFromHostHeader(requestText)
        } ?: return@runOnEdt
        result = RepeaterConnectionInfo(requestText, hostname, port, https)
    }
    return result
}

private fun findRepeaterInnerTabbedPane(container: Container): JTabbedPane? {
    val mainPane = findTabbedPaneContaining(container, "Repeater") ?: return null
    val idx = (0 until mainPane.tabCount)
        .firstOrNull { mainPane.getTitleAt(it).equals("Repeater", ignoreCase = true) } ?: return null
    val repeaterPanel = mainPane.getComponentAt(idx) as? Container ?: return null
    return findFirstTabbedPane(repeaterPanel)
}

private fun findTabbedPaneContaining(container: Container, tabTitle: String): JTabbedPane? {
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTabbedPane && (0 until comp.tabCount).any { comp.getTitleAt(it).equals(tabTitle, ignoreCase = true) }) {
            return comp
        }
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

private fun findFirstTabbedPane(container: Container): JTabbedPane? {
    val queue = ArrayDeque<Component>()
    container.components.forEach { queue.add(it) }
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTabbedPane) return comp
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

private val HTTP_VERBS = listOf("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")

private fun findRepeaterRequestText(container: Container): String? {
    val areas = mutableListOf<JTextArea>()
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTextArea) areas.add(comp)
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return areas.firstOrNull { area -> HTTP_VERBS.any { area.text.trimStart().startsWith(it) } }?.text
        ?: areas.firstOrNull { it.isEditable }?.text
}

private fun findRepeaterTargetUrl(container: Container): String? {
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTextField) {
            val text = comp.text?.trim() ?: ""
            if (text.startsWith("http://") || text.startsWith("https://")) return text
        }
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

private fun parseRepeaterTargetUrl(url: String): Triple<String, Int, Boolean>? {
    return try {
        val https = url.startsWith("https://")
        val withoutScheme = url.removePrefix("https://").removePrefix("http://").trimEnd('/')
        val colonIdx = withoutScheme.lastIndexOf(':')
        if (colonIdx >= 0) {
            val host = withoutScheme.substring(0, colonIdx)
            val port = withoutScheme.substring(colonIdx + 1).toIntOrNull() ?: if (https) 443 else 80
            Triple(host, port, https)
        } else {
            Triple(withoutScheme, if (https) 443 else 80, https)
        }
    } catch (_: Exception) { null }
}

private fun deriveTargetFromHostHeader(request: String): Triple<String, Int, Boolean>? {
    val hostValue = request.lines()
        .firstOrNull { it.trim().startsWith("Host:", ignoreCase = true) }
        ?.substringAfter(":")?.trim() ?: return null
    return if (hostValue.contains(":")) {
        val parts = hostValue.split(":")
        val port = parts[1].trim().toIntOrNull() ?: 80
        Triple(parts[0].trim(), port, port == 443)
    } else {
        Triple(hostValue, 80, false)
    }
}

private fun runOnEdt(block: () -> Unit) {
    if (EventQueue.isDispatchThread()) {
        block()
    } else {
        try { SwingUtilities.invokeAndWait(block) } catch (_: Exception) {}
    }
}