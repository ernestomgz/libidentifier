"""Conservative static framework indicators; no framework payload execution."""
from __future__ import annotations
from pathlib import PurePosixPath
from ..models import CodeLocator, FrameworkEvidence, FrameworkHint

# Exact runtime entry points, not generic AndroidX/Kotlin namespaces.
RULES = {
    "flutter": ("Flutter", {
        "Lio/flutter/embedding/engine/FlutterEngine;", "Lio/flutter/embedding/android/FlutterActivity;",
        "Lio/flutter/view/FlutterNativeView;",
    }, {"libflutter.so"}, "Dart application logic and package dependencies are not analyzed"),
    "react_native": ("React Native", {
        "Lcom/facebook/react/ReactInstanceManager;", "Lcom/facebook/react/ReactNativeHost;",
        "Lcom/facebook/react/bridge/CatalystInstanceImpl;",
    }, {"libreactnative.so", "libreactnativejni.so"}, "JavaScript and Hermes application logic and dependencies are not analyzed"),
    "jetpack_compose": ("Jetpack Compose", {
        "Landroidx/compose/runtime/Composer;", "Landroidx/compose/runtime/ComposerImpl;",
        "Landroidx/compose/ui/platform/AndroidComposeView;",
    }, set(), "DEX structure is analyzed; Compose usage and UI behavior are not established"),
    "cordova": ("Cordova", {
        "Lorg/apache/cordova/CordovaActivity;", "Lorg/apache/cordova/CordovaWebViewImpl;",
        "Lorg/apache/cordova/PluginManager;",
    }, set(), "JavaScript application logic and dependencies are not analyzed"),
    "unity": ("Unity", {
        "Lcom/unity3d/player/UnityPlayer;", "Lcom/unity3d/player/UnityPlayerActivity;",
    }, {"libunity.so"}, "Unity managed code and IL2CPP application logic are not analyzed"),
    "dotnet_android": ("Xamarin / .NET MAUI", {
        "Lmono/android/Runtime;", "Lmono/MonoPackageManager;", "Lmono/MonoPackageManager_Resources;",
    }, {"libmonodroid.so", "libmonosgen-2.0.so"}, ".NET assemblies and MAUI application logic are not analyzed; Xamarin versus MAUI is not always distinguishable"),
}
ASSETS = {
    "flutter": {"assets/flutter_assets/" + x for x in (
        "AssetManifest.json", "AssetManifest.bin", "NOTICES.Z", "kernel_blob.bin",
        "isolate_snapshot_data", "vm_snapshot_data")},
    "react_native": {"assets/index.android.bundle"},
    "cordova": {"assets/www/cordova.js"},
    "unity": {"assets/bin/Data/globalgamemanagers", "assets/bin/Data/Managed/Metadata/global-metadata.dat"},
    "dotnet_android": {"assemblies/" + x for x in (
        "assemblies.blob", "assemblies.manifest", "mscorlib.dll", "Mono.Android.dll",
        "Microsoft.Maui.dll", "Microsoft.Maui.Controls.dll")},
}


def detect_frameworks(members, classes, elf_features, *, container: str) -> list[FrameworkHint]:
    """Combine independent evidence kinds; multiple ABIs do not increase confidence.

    A single exact class definition is a low-confidence presence hint. Filenames
    alone never suffice; parsed native artifacts need corroboration.
    """
    results = []
    for framework_id, (name, descriptors, native_names, limitation) in RULES.items():
        evidence, kinds, found_classes = [], set(), set()

        def add(kind, indicator, location):
            kinds.add(kind)
            evidence.append(FrameworkEvidence(indicator, location))

        for cls in classes:
            if cls.descriptor in descriptors:
                found_classes.add(cls.descriptor)
                add("dex", "defined framework runtime class", cls.locator)
        for elf, artifact in elf_features:
            basename = PurePosixPath(artifact.member or artifact.path or "").name
            loc = CodeLocator(container, artifact.member, sha256=elf.sha256)
            if basename in native_names or elf.soname in native_names:
                add("native", "parsed ELF runtime: " + (elf.soname or basename), loc)
            if framework_id == "flutter":
                for symbol in elf.exported_symbols:
                    if symbol in {"FlutterEngineRun", "FlutterEngineInitialize"}:
                        add("symbol", "ELF exported symbol: " + symbol, loc)
        for m in members:
            if m.name not in ASSETS.get(framework_id, set()):
                continue
            if framework_id == "cordova" and not any(marker in m.data for marker in (
                b"cordova.define", b'define("cordova', b"define('cordova")):
                continue
            add("asset", name + " asset layout" + (" with bootstrap marker" if framework_id == "cordova" else " (content not analyzed)"),
                CodeLocator(container, m.name, sha256=m.sha256))
        if not found_classes and not ({"native", "asset"} <= kinds or "symbol" in kinds):
            continue
        confidence = "low"
        if len(found_classes) >= 2 or len(kinds) >= 2:
            confidence = "medium"
        if len(kinds) >= 3 or ({"dex", "native"} <= kinds and len(found_classes) >= 2):
            confidence = "high"
        evidence.sort(key=lambda e: (e.location.member or "", e.location.class_descriptor or "", e.indicator))
        results.append(FrameworkHint(
            name=name, evidence="; ".join(sorted({e.indicator for e in evidence})),
            member=evidence[0].location.member, confidence=confidence,
            limitations=[limitation, "Presence does not prove active use; no framework version is inferred"],
            framework_id=framework_id, evidence_records=evidence,
            application_logic="dex_structure_only" if framework_id == "jetpack_compose" else "not_supported",
        ))
    return sorted(results, key=lambda h: h.name)


def framework_hints_from_names(member_names, classes):
    """Legacy internal helper: filenames alone no longer establish presence."""
    return detect_frameworks([], classes, [], container="")
