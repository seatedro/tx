//! The Wayland interfaces the clipboard server speaks, and their opcodes,
//! from `wayland.xml` (wayland 1.25), `wlr-data-control-unstable-v1.xml`
//! and `ext-data-control-v1.xml` (wayland-protocols 1.48).
//!
//! A request's or event's opcode is its position in its interface's
//! definition. Each interface here lists all of them, including ones the
//! server ignores, so that a message is always recognized.
//!
//! The two data control protocols have the same requests and events in
//! the same order, so `data_control` describes both, and only their
//! interface names differ.

/// The display, always object 1.
pub const display = struct {
    pub const name = "wl_display";
    pub const id: u32 = 1;

    pub const Request = enum(u16) {
        sync = 0,
        get_registry = 1,
    };

    pub const Event = enum(u16) {
        @"error" = 0,
        delete_id = 1,
    };

    pub const Error = enum(u32) {
        invalid_object = 0,
        invalid_method = 1,
        no_memory = 2,
        implementation = 3,
    };
};

pub const registry = struct {
    pub const name = "wl_registry";

    pub const Request = enum(u16) {
        bind = 0,
    };

    pub const Event = enum(u16) {
        global = 0,
        global_remove = 1,
    };
};

/// Has no requests. The server destroys it after `done`.
pub const callback = struct {
    pub const name = "wl_callback";

    pub const Event = enum(u16) {
        done = 0,
    };
};

pub const seat = struct {
    pub const name = "wl_seat";

    pub const Request = enum(u16) {
        get_pointer = 0,
        get_keyboard = 1,
        get_touch = 2,
        /// Since version 5. A destructor.
        release = 3,
    };

    pub const Event = enum(u16) {
        capabilities = 0,
        /// Since version 2.
        name = 1,
    };

    pub const Error = enum(u32) {
        missing_capability = 0,
    };
};

pub const compositor = struct {
    pub const name = "wl_compositor";

    pub const Request = enum(u16) {
        create_surface = 0,
        create_region = 1,
        /// Since version 7. A destructor.
        release = 2,
    };
};

pub const surface = struct {
    pub const name = "wl_surface";

    pub const Request = enum(u16) {
        /// A destructor.
        destroy = 0,
        attach = 1,
        damage = 2,
        /// Creates a wl_callback.
        frame = 3,
        set_opaque_region = 4,
        set_input_region = 5,
        commit = 6,
        /// Since version 2.
        set_buffer_transform = 7,
        /// Since version 3.
        set_buffer_scale = 8,
        /// Since version 4.
        damage_buffer = 9,
        /// Since version 5.
        offset = 10,
        /// Since version 7. Creates a wl_callback.
        get_release = 11,
    };
};

pub const region = struct {
    pub const name = "wl_region";

    pub const Request = enum(u16) {
        /// A destructor.
        destroy = 0,
        add = 1,
        subtract = 2,
    };
};

pub const output = struct {
    pub const name = "wl_output";

    pub const Request = enum(u16) {
        /// Since version 3. A destructor.
        release = 0,
    };

    pub const Event = enum(u16) {
        geometry = 0,
        mode = 1,
        /// Since version 2.
        done = 2,
        /// Since version 2.
        scale = 3,
        /// Since version 4.
        name = 4,
        /// Since version 4.
        description = 5,
    };

    pub const Mode = struct {
        pub const current: u32 = 0x1;
        pub const preferred: u32 = 0x2;
    };
};

/// zwlr_data_control_v1 (version 2 adds the primary selection) and
/// ext_data_control_v1 (version 1 has it).
pub const data_control = struct {
    pub const Protocol = enum {
        wlr,
        ext,

        pub fn names(p: Protocol) Names {
            return switch (p) {
                .wlr => .{
                    .manager = "zwlr_data_control_manager_v1",
                    .device = "zwlr_data_control_device_v1",
                    .source = "zwlr_data_control_source_v1",
                    .offer = "zwlr_data_control_offer_v1",
                },
                .ext => .{
                    .manager = "ext_data_control_manager_v1",
                    .device = "ext_data_control_device_v1",
                    .source = "ext_data_control_source_v1",
                    .offer = "ext_data_control_offer_v1",
                },
            };
        }
    };

    pub const Names = struct {
        manager: []const u8,
        device: []const u8,
        source: []const u8,
        offer: []const u8,
    };

    pub const manager = struct {
        pub const Request = enum(u16) {
            create_data_source = 0,
            get_data_device = 1,
            /// A destructor.
            destroy = 2,
        };
    };

    pub const device = struct {
        pub const Request = enum(u16) {
            set_selection = 0,
            /// A destructor.
            destroy = 1,
            /// Since zwlr version 2.
            set_primary_selection = 2,
        };

        pub const Event = enum(u16) {
            /// Creates an offer, with a server-allocated ID.
            data_offer = 0,
            selection = 1,
            finished = 2,
            /// Since zwlr version 2.
            primary_selection = 3,
        };

        pub const Error = enum(u32) {
            used_source = 1,
        };
    };

    pub const source = struct {
        pub const Request = enum(u16) {
            offer = 0,
            /// A destructor.
            destroy = 1,
        };

        pub const Event = enum(u16) {
            /// Carries a file descriptor.
            send = 0,
            cancelled = 1,
        };

        pub const Error = enum(u32) {
            invalid_offer = 1,
        };
    };

    pub const offer = struct {
        pub const Request = enum(u16) {
            /// Carries a file descriptor.
            receive = 0,
            /// A destructor.
            destroy = 1,
        };

        pub const Event = enum(u16) {
            offer = 0,
        };
    };
};

/// IDs from here up are the server's to allocate, such as offers'.
pub const server_id_start: u32 = 0xff00_0000;
