use super::*;

fn lim() -> Limits {
    Limits::DEFAULT
}

#[test]
fn builds_a_tree_with_local_names_and_entities() {
    let doc = r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="urn:x" Name="A &amp; B">
  <Node Name="srv" Hostname="h.example.test"><Sub>t &lt; &#65;<![CDATA[<raw>]]></Sub></Node>
  <Empty/>
</mrng:Connections>"#;
    let root = parse(doc, &lim(), "t").expect("parse");
    assert_eq!(root.name, "Connections");
    assert_eq!(root.attr("Name"), Some("A & B"));
    let node = root.child("Node").expect("node");
    assert_eq!(node.attr("Hostname"), Some("h.example.test"));
    assert_eq!(node.child_text("Sub"), Some("t < A<raw>"));
    assert_eq!(root.path_text(&["Node", "Sub"]), Some("t < A<raw>"));
    assert_eq!(root.child("Empty").map(|e| e.text.as_str()), Some(""));
    assert_eq!(root.first_text(&["Nope", "Node"]), None);
    assert_eq!(root.children_named("Node").count(), 1);
}

#[test]
fn doctype_is_refused_wherever_it_appears() {
    let e = parse("<!DOCTYPE x [<!ENTITY a \"b\">]><x/>", &lim(), "t");
    assert_eq!(e, Err(ImportError::Doctype { at: 0 }));
    let e = parse("<?xml version=\"1.0\"?>\n<!DOCTYPE x><x/>", &lim(), "t");
    assert!(matches!(e, Err(ImportError::Doctype { at }) if at > 0));
}

#[test]
fn unknown_entities_are_a_format_error() {
    assert!(matches!(parse("<x>&foo;</x>", &lim(), "t"), Err(ImportError::Format { .. })));
    assert!(matches!(parse("<x a=\"&foo;\"/>", &lim(), "t"), Err(ImportError::Format { .. })));
    assert_eq!(parse("<x>&#x41;&quot;</x>", &lim(), "t").expect("ok").text, "A\"");
}

#[test]
fn depth_count_and_text_caps_hold() {
    let mut l = lim();
    l.max_xml_depth = 3;
    assert!(parse("<a><b><c/></b></a>", &l, "t").is_ok());
    assert_eq!(parse("<a><b><c><d/></c></b></a>", &l, "t"), Err(ImportError::limits("nesting depth")));
    l = lim();
    l.max_xml_elements = 2;
    assert_eq!(parse("<a><b/><c/></a>", &l, "t"), Err(ImportError::limits("element count")));
    l = lim();
    l.max_text = 4;
    assert_eq!(parse("<a>12345</a>", &l, "t"), Err(ImportError::limits("text length")));
    assert_eq!(parse("<a>12<b/>345</a>", &l, "t"), Err(ImportError::limits("text length")));
    assert_eq!(parse("<a x=\"12345\"/>", &l, "t"), Err(ImportError::limits("attribute length")));
    assert!(parse("<a x=\"1234\">1234</a>", &l, "t").is_ok());
}

#[test]
fn malformed_documents_report_an_offset_only() {
    for doc in ["", "<a>", "<a></b>", "<a/><b/>", "text", "<a b='1' b='2'/>"] {
        let e = parse(doc, &lim(), "fmt").expect_err(doc);
        assert_eq!(e.code(), "import.format", "{doc}");
        let msg = e.to_string();
        assert!(msg.starts_with("not a valid fmt file ("), "{msg}");
    }
}

#[test]
fn deep_nesting_bomb_does_not_recurse() {
    let doc = format!("{}{}", "<a>".repeat(10_000), "</a>".repeat(10_000));
    assert_eq!(parse(&doc, &lim(), "t"), Err(ImportError::limits("nesting depth")));
}
