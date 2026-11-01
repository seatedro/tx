//! Interface names and opcodes for the interfaces server.zig implements, from
//! wayland.xml and the wlr and ext data-control protocol XML. Requests and
//! events are numbered apart, in the order each interface declares them.

pub const display = struct {
    pub const name = "wl_display";
    /// wl_display is object 1 on every connection.
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
        release = 3,
    };

    pub const Event = enum(u16) {
        capabilities = 0,
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
        release = 2,
    };
};

pub const surface = struct {
    pub const name = "wl_surface";

    pub const Request = enum(u16) {
        destroy = 0,
        attach = 1,
        damage = 2,
        frame = 3,
        set_opaque_region = 4,
        set_input_region = 5,
        commit = 6,
        set_buffer_transform = 7,
        set_buffer_scale = 8,
        damage_buffer = 9,
        offset = 10,
        get_release = 11,
    };
};

pub const region = struct {
    pub const name = "wl_region";

    pub const Request = enum(u16) {
        destroy = 0,
        add = 1,
        subtract = 2,
    };
};

pub const output = struct {
    pub const name = "wl_output";

    pub const Request = enum(u16) {
        release = 0,
    };

    pub const Event = enum(u16) {
        geometry = 0,
        mode = 1,
        done = 2,
        scale = 3,
        name = 4,
        description = 5,
    };

    pub const Mode = struct {
        pub const current: u32 = 0x1;
        pub const preferred: u32 = 0x2;
    };
};

/// The wlr and ext data-control protocols have the same requests, events and
/// opcodes under different interface names. The wlr device has the primary
/// selection from version 2; the ext device always has it.
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
            destroy = 2,
        };
    };

    pub const device = struct {
        pub const Request = enum(u16) {
            set_selection = 0,
            destroy = 1,
            set_primary_selection = 2,
        };

        pub const Event = enum(u16) {
            data_offer = 0,
            selection = 1,
            finished = 2,
            primary_selection = 3,
        };

        pub const Error = enum(u32) {
            used_source = 1,
        };
    };

    pub const source = struct {
        pub const Request = enum(u16) {
            offer = 0,
            destroy = 1,
        };

        pub const Event = enum(u16) {
            send = 0,
            cancelled = 1,
        };

        pub const Error = enum(u32) {
            invalid_offer = 1,
        };
    };

    pub const offer = struct {
        pub const Request = enum(u16) {
            receive = 0,
            destroy = 1,
        };

        pub const Event = enum(u16) {
            offer = 0,
        };
    };
};

/// The server allocates object ids from here up, and programs allocate the ids
/// below. libwayland calls it WL_SERVER_ID_START.
pub const server_id_start: u32 = 0xff00_0000;
