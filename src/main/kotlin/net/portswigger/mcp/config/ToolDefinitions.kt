package net.portswigger.mcp.config

data class ToolDef(
    val name: String,
    val displayName: String,
    val category: String,
    val proOnly: Boolean = false
)

object ToolDefinitions {

    val all: List<ToolDef> = listOf(
        // Repeater
        ToolDef("create_repeater_tab", "Create Repeater tab", "Repeater"),
        ToolDef("list_repeater_tabs", "List Repeater tabs", "Repeater"),
        ToolDef("get_repeater_tab", "Get tab request + target", "Repeater"),
        ToolDef("send_repeater_tab_request", "Send tab request", "Repeater"),

        // Proxy
        ToolDef("get_proxy_http_history_regex", "Get HTTP history (regex filter)", "Proxy"),
        ToolDef("get_proxy_http_history_item", "Get HTTP history item by index", "Proxy"),
        ToolDef("get_proxy_websocket_history", "Get WebSocket history", "Proxy"),
        ToolDef("get_proxy_websocket_history_regex", "Get WebSocket history (regex filter)", "Proxy"),

        // Scanner (Pro only)
        ToolDef("get_scanner_issues", "Get scanner issues", "Scanner", proOnly = true),
        ToolDef("start_active_scan", "Start active scan", "Scanner", proOnly = true),
        ToolDef("start_passive_scan", "Start passive scan", "Scanner", proOnly = true),
        ToolDef("generate_collaborator_payload", "Generate Collaborator payload", "Scanner", proOnly = true),
        ToolDef("get_collaborator_interactions", "Get Collaborator interactions", "Scanner", proOnly = true),

        // Intruder
        ToolDef("send_to_intruder", "Send to Intruder", "Intruder"),

        // Utilities
        ToolDef("url_encode", "URL encode", "Utilities"),
        ToolDef("url_decode", "URL decode", "Utilities"),
        ToolDef("base64_encode", "Base64 encode", "Utilities"),
        ToolDef("base64_decode", "Base64 decode", "Utilities"),
        ToolDef("generate_random_string", "Generate random string", "Utilities"),
        ToolDef("extract_from_response", "Extract from response (regex)", "Utilities"),

        // Editor
        ToolDef("get_active_editor_contents", "Get active editor contents", "Editor"),
        ToolDef("set_active_editor_contents", "Set active editor contents", "Editor"),
    )

    val categoryOrder = listOf(
        "Repeater", "Proxy", "Scanner", "Intruder", "Utilities", "Editor"
    )

    val byCategory: Map<String, List<ToolDef>> = all.groupBy { it.category }
}
