/**
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * Smsprpl is a mock protocol plugin for Pidgin and libpurple. You can create
 * accounts with it, sign on and off, add buddies, and send and receive IMs,
 * all without connecting to a server!
 *
 * Beyond that basic functionality, smsprpl supports presence and
 * away/available messages, offline messages, user info, typing notification,
 * privacy allow/block lists, chat rooms, whispering, room lists, and protocol
 * icons and emblems. Notable missing features are file transfer and account
 * registration and authentication.
 *
 * Smsprpl is intended as an example of how to write a libpurple protocol
 * plugin. It doesn't contain networking code or an event loop, but it does
 * demonstrate how to use the libpurple API to do pretty much everything a prpl
 * might need to do.
 *
 * Smsprpl is also a useful tool for hacking on Pidgin, Finch, and other
 * libpurple clients. It's a full-featured protocol plugin, but doesn't depend
 * on an external server, so it's a quick and easy way to exercise test new
 * code. It also allows you to work while you're disconnected.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */


#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <glib.h>

/* If you're using this as the basis of a prpl that will be distributed
 * separately from libpurple, remove the internal.h include below and replace
 * it with code to include your own config.h or similar.  If you're going to
 * provide for translation, you'll also need to setup the gettext macros. */
#include "internal.h"

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "cmds.h"
#include "conversation.h"
#include "connection.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "roomlist.h"
#include "status.h"
#include "util.h"
#include "version.h"
#include "udp.h"
#include "protocol.h"
#include "json.h"
#include "smsprpl.h"
#include "network.c"

#define SMSPRPL_ID "prpl-sms"

#define SMS_STATUS_ONLINE   "online"
#define SMS_STATUS_AWAY     "away"
#define SMS_STATUS_OFFLINE  "offline"


static char *smsprpl_status_text(PurpleBuddy *buddy) {
    smsprpl_debug_info("smsprpl", "getting %s's status text for %s\n",
            buddy->name, buddy->account->username);

    if (purple_find_buddy(buddy->account, buddy->name)) {
        PurplePresence *presence = purple_buddy_get_presence(buddy);
        PurpleStatus *status = purple_presence_get_active_status(presence);
        const char *name = purple_status_get_name(status);
        const char *message = purple_status_get_attr_string(status, "message");
        char *text;

        purple_presence_switch_status (presence, SMS_STATUS_ONLINE);

        if (message && strlen(message) > 0)
            text = g_strdup_printf("%s: %s", name, message);
        else
            text = g_strdup(name);

        smsprpl_debug_info("smsprpl", "%s's status text is %s\n", buddy->name, text);
        return text;

    } else {
        smsprpl_debug_info("smsprpl", "...but %s is not logged in\n", buddy->name);
        return g_strdup("Not logged in");
    }
}


static GList *smsprpl_status_types(PurpleAccount *acct)
{
    GList *types = NULL;
    PurpleStatusType *type;

    smsprpl_debug_info("smsprpl", "returning status types for %s: %s, %s, %s\n",
            acct->username,
            SMS_STATUS_ONLINE, SMS_STATUS_AWAY, SMS_STATUS_OFFLINE);

    type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
            SMS_STATUS_ONLINE, NULL, TRUE, TRUE, FALSE,
            "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
            NULL);
    types = g_list_prepend(types, type);

    type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
            SMS_STATUS_AWAY, NULL, TRUE, TRUE, FALSE,
            "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
            NULL);
    types = g_list_prepend(types, type);

    type = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE,
            SMS_STATUS_OFFLINE, NULL, TRUE, TRUE, FALSE,
            "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
            NULL);
    types = g_list_prepend(types, type);

    return g_list_reverse(types);
}


static void process_noti (PurpleConnection *gc, json_val_t *val)
{
}

static void process_contact (PurpleConnection *gc, json_val_t *val)
{
    PurpleBuddy *b = NULL;
    PurpleGroup *g = NULL;
    char *phone = protocol_get_string(val, "phone");
    char *name = protocol_get_string(val, "name");
    char *group = protocol_get_string(val, "group");
    if (phone == NULL || name == NULL|| group == NULL) {
        smsprpl_debug_error(PRPL_TAG, "contact data error\n");
        return;
    }
    
    smsprpl_debug_info("smsprpl", "recieve contact: name:%s; phone:%s; group:%s\n", name, phone, group);
    g = purple_find_group(group);
    if (!g) {
        g = purple_group_new(group);
    }
    b = purple_find_buddy(gc->account, phone);
    if (!b) {
        b = purple_buddy_new(gc->account, phone, name);
    }
    purple_blist_add_buddy(b, NULL, g, NULL);
    purple_blist_alias_buddy(b, name);
}

static void process_auth (PurpleConnection *gc, json_val_t *val)
{
    char *result = protocol_get_string(val, "result");
    smsprpl_debug_info("smsprpl", "the auth result is %s\n", result);
    if (strcmp(result, "success") == 0) {
        smsprpl_debug_info ("smsprpl", "auth succeed\n");
        purple_connection_update_progress(gc, _("Connected"), 1, 2);
        purple_connection_set_state(gc, PURPLE_CONNECTED);
    } else {
        smsprpl_debug_error ("smsprpl", "auth failed\n");
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Unable to connect"));
    }
}

static void process_msg(PurpleConnection *gc, json_val_t *val)
{
    char *who = protocol_get_string(val, "who");
    char *msg = protocol_get_string(val, "msg");
    if (who == NULL || msg == NULL) {
        smsprpl_debug_error(PRPL_TAG, "string 'who' or 'msg' is null\n");
        return;
    }
    smsprpl_debug_info(PRPL_TAG, "message come from %s: %s\n", who, msg);
    serv_got_im(gc, who, msg, 0, time(NULL));
}

static void process_resp (PurpleConnection *gc, json_val_t *val)
{
   //char *resp = protocol_get_string_val(val, "resp", NULL); 
}

static void process (PurpleConnection *gc, json_val_t *root)
{
    char *type;
    if (root == NULL)
        return;
    type = protocol_get_string(root, "type");
    smsprpl_debug_info("smsprpl", "the package type is %s\n", type);
    if (strcmp(type, "resp") == 0)
        process_resp(gc, root);
    if (strcmp(type, "contact") == 0)
        process_contact(gc, root);
    if (strcmp(type, "auth") == 0)
        process_auth(gc, root);
    if (strcmp(type, "msg") == 0)
        process_msg(gc, root);
    if (strcmp(type, "noti") == 0)
        process_noti(gc, root);
}

static void input_cb (gpointer data, gint source, PurpleInputCondition cond)
{
    PurpleConnection *gc = data;
    PtlData *ptl_data = gc->proto_data;
    int read_num = 0;
    char buffer[BUFFER_SIZE]; 
    Buffer ctx;
    json_val_t *val;
    char dist[20];
    

    buffer_init(&ctx);

    if (source <= 0)
        return;

    smsprpl_debug_info("smsprpl", "received data\n");
    
    while (1) {
        read_num = read(source, buffer, BUFFER_SIZE);
        if (read_num <= 0)
            break;
        buffer_update(&ctx, buffer, read_num);
    }

    val = protocol_decrypt_string(&ctx, ptl_data->header, dist);

    val = protocol_get_val(val, "data");
    
    process(gc, val);

    buffer_free(&ctx);
}

static void udp_listen_cb(int sockfd, gpointer data)
{
    PurpleConnection *gc = data;
    PtlData *ptl_data = (PtlData*)gc->proto_data;
    ptl_data->udp_listenfd = sockfd;
    ptl_data->udp_listen_data = NULL;

    smsprpl_debug_info("smsprpl", "listen setup\n");
    ptl_data->udp_input_read = purple_input_add(sockfd, PURPLE_INPUT_READ, input_cb, gc);
    if (ptl_data->udp_input_read == -1) {
        smsprpl_debug_error("smsprpl", "add input error\n");
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Add input error"));
    }
}


static void smsprpl_login(PurpleAccount *acct)
{
    PurpleConnection *gc = purple_account_get_connection(acct);
    char *username = (char *)purple_account_get_username(acct);
    char *password = (char *)purple_account_get_password(acct);
    PtlData *ptl_data = (PtlData*)malloc(sizeof(PtlData));
    PtlHeader *header = (PtlHeader*)malloc(sizeof(PtlHeader));

    smsprpl_debug_info(PRPL_TAG, "enter login\n");

    protocol_init(header);
    protocol_set_key(header, username, password);
    header->from = "1";
    header->to = "2";

    ptl_data->udp_input_read = -1;
    ptl_data->udp_listen_data = NULL;
    ptl_data->udp_listenfd = -1;
    ptl_data->udp_send_sock = NULL;
    ptl_data->header = header;

    gc->proto_data = ptl_data;

    ptl_data->udp_send_sock = udp_init_broadcast(8888);

    purple_connection_update_progress(gc, _("Connecting"), 0, 2); 

    if (protocol_send_auth(ptl_data->udp_send_sock, header, username, password) == -1) {
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Send auth failed"));
        smsprpl_debug_error(PRPL_TAG, "send auth failed\n");
        return;
    }

    smsprpl_debug_info(PRPL_TAG, "logging in %s\n", acct->username);
    
    
    purple_network_listen_map_external(FALSE);
    ptl_data->udp_listen_data = purple_network_listen(8888, SOCK_DGRAM, udp_listen_cb, gc);

    if (ptl_data->udp_listen_data == NULL) {
        smsprpl_debug_error(PRPL_TAG, "listen auth failed\n");
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Listen auth failed"));
        return;
    }
}

static void smsprpl_close(PurpleConnection *gc)
{
    PtlData *ptl_data;

    smsprpl_debug_info(PRPL_TAG, "enter close\n");
    if (gc == NULL)
        return;
    if (gc->proto_data == NULL)
        return;
    ptl_data = (PtlData*)gc->proto_data;
    if (ptl_data->udp_listenfd > 0) {
        close(ptl_data->udp_listenfd);
    }
    if (ptl_data->udp_listen_data != NULL) {
        purple_network_listen_cancel(ptl_data->udp_listen_data);
    }
    if (ptl_data->udp_input_read > 0) {
        purple_input_remove(ptl_data->udp_input_read);
    }
    if (ptl_data->udp_send_sock != NULL) {
        udp_close(ptl_data->udp_send_sock);
    }
    free(ptl_data);
}

static int smsprpl_send_im(PurpleConnection *gc, const char *who,
        const char *message, PurpleMessageFlags flags)
{
    //PtlData *ptl_data = (PtlData*)gc->proto_data;

    smsprpl_debug_info("smsprpl", "sending message to %s: %s\n",
            who, message);

   // if (protocol_send_msg(ptl_data->udp_send_sock, who, message) != 0) {
   //     smsprpl_debug_info("smsprpl", "Send msg error\n");
   //     purple_conv_present_error(who, gc->account, _("Send msg error"));
   //     return 0;
   // }

    return 1;
}



static void smsprpl_set_status(PurpleAccount *acct, PurpleStatus *status) {
  const char *msg = purple_status_get_attr_string(status, "message");
  purple_debug_info("smsprpl", "setting %s's status to %s: %s\n",
                    acct->username, purple_status_get_name(status), msg);
}

static const char *smsprpl_list_icon(PurpleAccount *acct, PurpleBuddy *buddy)
{
  return "sms";
}

/*
 * prpl stuff. see prpl.h for more information.
 */

static PurplePluginProtocolInfo prpl_info =
{
    0,  /* options */
    NULL,               /* user_splits, initialized in smsprpl_init() */
    NULL,               /* protocol_options, initialized in smsprpl_init() */
    {   /* icon_spec, a PurpleBuddyIconSpec */
        "png,jpg,gif",                   /* format */
        0,                               /* min_width */
        0,                               /* min_height */
        128,                             /* max_width */
        128,                             /* max_height */
        10000,                           /* max_filesize */
        PURPLE_ICON_SCALE_DISPLAY,       /* scale_rules */
    },
    smsprpl_list_icon,                  /* list_icon */
    NULL,                                /* list_emblem */
    smsprpl_status_text,                /* status_text */
    NULL,               /* tooltip_text */
    smsprpl_status_types,               /* status_types */
    NULL,                                /* blist_node_menu */
    NULL,                                /* chat_info */
    NULL,                                /* chat_info_defaults */
    smsprpl_login,                      /* login */
    smsprpl_close,                      /* close */
    smsprpl_send_im,                    /* send_im */
    NULL,                   /* set_info */
    NULL,                /* send_typing */
    NULL,                   /* get_info */
    smsprpl_set_status,                 /* set_status */
    NULL,                   /* set_idle */
    NULL,              /* change_passwd */
    NULL,                  /* add_buddy */
    NULL,                /* add_buddies */
    NULL,               /* remove_buddy */
    NULL,             /* remove_buddies */
    NULL,                 /* add_permit */
    NULL,                   /* add_deny */
    NULL,                 /* rem_permit */
    NULL,                   /* rem_deny */
    NULL,            /* set_permit_deny */
    NULL,                  /* join_chat */
    NULL,                /* reject_chat */
    NULL,              /* get_chat_name */
    NULL,                /* chat_invite */
    NULL,                 /* chat_leave */
    NULL,               /* chat_whisper */
    NULL,                  /* chat_send */
    NULL,                                /* keepalive */
    NULL,              /* register_user */
    NULL,                /* get_cb_info */
    NULL,                                /* get_cb_away */
    NULL,                /* alias_buddy */
    NULL,                /* group_buddy */
    NULL,               /* rename_group */
    NULL,                                /* buddy_free */
    NULL,               /* convo_closed */
    NULL,                  /* normalize */
    NULL,             /* set_buddy_icon */
    NULL,               /* remove_group */
    NULL,                                /* get_cb_real_name */
    NULL,             /* set_chat_topic */
    NULL,                                /* find_blist_chat */
    NULL,          /* roomlist_get_list */
    NULL,            /* roomlist_cancel */
    NULL,   /* roomlist_expand_category */
    NULL,           /* can_receive_file */
    NULL,                                /* send_file */
    NULL,                                /* new_xfer */
    NULL,            /* offline_message */
    NULL,                                /* whiteboard_prpl_ops */
    NULL,                                /* send_raw */
    NULL,                                /* roomlist_room_serialize */
    NULL,                                /* unregister_user */
    NULL,                                /* send_attention */
    NULL,                                /* get_attention_types */
    sizeof(PurplePluginProtocolInfo),    /* struct_size */
    NULL,                                /* get_account_text_table */
    NULL,                                /* initiate_media */
    NULL,                                /* get_media_caps */
    NULL,                                /* get_moods */
    NULL,                                /* set_public_alias */
    NULL,                                /* get_public_alias */
    NULL,                                /* add_buddy_with_invite */
    NULL                                 /* add_buddies_with_invite */
};

static void smsprpl_init(PurplePlugin *plugin)
{
    smsprpl_debug_info("smsprpl", "starting up\n");
}

static void smsprpl_destroy(PurplePlugin *plugin) {
    smsprpl_debug_info("smsprpl", "shutting down\n");
}


static PurplePluginInfo info =
{
    PURPLE_PLUGIN_MAGIC,                                     /* magic */
    PURPLE_MAJOR_VERSION,                                    /* major_version */
    PURPLE_MINOR_VERSION,                                    /* minor_version */
    PURPLE_PLUGIN_PROTOCOL,                                  /* type */
    NULL,                                                    /* ui_requirement */
    0,                                                       /* flags */
    NULL,                                                    /* dependencies */
    PURPLE_PRIORITY_DEFAULT,                                 /* priority */
    SMSPRPL_ID,                                             /* id */
    "SMS - Send sms via phone",                                 /* name */
    DISPLAY_VERSION,                                         /* version */
    N_("SMS Protocol Plugin"),                              /* summary */
    N_("SMS Protocol Plugin"),                              /* description */
    NULL,                                                    /* author */
    PURPLE_WEBSITE,                                          /* homepage */
    NULL,                                                    /* load */
    NULL,                                                    /* unload */
    smsprpl_destroy,                                        /* destroy */
    NULL,                                                    /* ui_info */
    &prpl_info,                                              /* extra_info */
    NULL,                                                    /* prefs_info */
    NULL,                                                    /* actions */
    NULL,                                                    /* padding... */
    NULL,
    NULL,
    NULL,
};

PURPLE_INIT_PLUGIN(sms, smsprpl_init, info);
