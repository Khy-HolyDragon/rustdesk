use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        // "data:image/png;base64,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".into()
        "data:image/png;base64,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".into()
    }
}
