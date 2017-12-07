/*
 * Copyright 2016 Google Inc.
 * author: Edward Hervey <bilboed@bilboed.com>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <locale.h>

#include <stdlib.h>
#include <glib.h>
#include <gst/gst.h>
#include <gst/pbutils/pbutils.h>

#ifndef LOCAL_FUZZ_BUILD
GST_PLUGIN_STATIC_DECLARE (coreelements);
GST_PLUGIN_STATIC_DECLARE (playback);
GST_PLUGIN_STATIC_DECLARE (typefindfunctions);
GST_PLUGIN_STATIC_DECLARE (app);
GST_PLUGIN_STATIC_DECLARE (ogg);
GST_PLUGIN_STATIC_DECLARE (theora);
GST_PLUGIN_STATIC_DECLARE (vorbis);
#endif

/* push-based discoverer fuzzing target
 *
 * This application can be compiled with libFuzzer to simulate
 * a push-based discoverer execution.
 *
 * To reproduce the failing behaviour, use:
 * $ gst-discoverer-1.0 pushfile:///...
 *
 * The goal is to cover basic usage of demuxers, parsers and
 * base decoder elements.
 *
 * When compiling, only link the required demuxer/parser/decoder
 * plugins and keep it to a limited range (ex: ogg/theora/vorbis)
 *
 **/

const guint8 *fuzztesting_data;
size_t fuzztesting_size;
guint64 offset;

static void
need_data_cb (GstElement * source, guint length, guint8 * data)
{
  GstBuffer *buf;
  GstFlowReturn flowret;

  GST_DEBUG_OBJECT (source, "lenght:%u data:%p", length, data);

  if (offset >= fuzztesting_size) {
    g_signal_emit_by_name (G_OBJECT (source), "end-of-stream", &flowret);
    return;
  }

  if (length == -1)
    length = fuzztesting_size - offset;

  buf =
      gst_buffer_new_wrapped_full (0, (gpointer) data, fuzztesting_size, offset,
      length, NULL, NULL);
  g_signal_emit_by_name (G_OBJECT (source), "push-buffer", buf, &flowret);
  gst_buffer_unref (buf);
  offset += length;
}

static gboolean
seek_data_cb (GstElement * source, guint64 reqoffset, gpointer user_data)
{
  GST_DEBUG_OBJECT (source, "reqoffset %" G_GUINT64_FORMAT, reqoffset);
  if (reqoffset >= fuzztesting_size)
    return FALSE;
  offset = reqoffset;
  return TRUE;
}

static void
appsrc_configuration (GstDiscoverer * dc, GstElement * source, gpointer data)
{
  GstBuffer *buf;
  GstFlowReturn ret;

  g_object_set (G_OBJECT (source), "size", fuzztesting_size, NULL);
#ifndef PULL_MODE_FUZZER
  /* Create buffer from fuzztesting_data which shouldn't be freed */
  buf =
      gst_buffer_new_wrapped_full (0, (gpointer) fuzztesting_data,
      fuzztesting_size, 0, fuzztesting_size, NULL, NULL);
  g_signal_emit_by_name (G_OBJECT (source), "push-buffer", buf, &ret);
  gst_buffer_unref (buf);
#else
  g_object_set (source, "stream-type", 2, NULL);
  offset = 0;
  g_signal_connect (source, "need-data", (GCallback) need_data_cb,
      (gpointer) fuzztesting_data);
  g_signal_connect (source, "seek-data", (GCallback) seek_data_cb, NULL);
#endif
}

static void
custom_logger (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer unused_data)
{
  if (log_level & G_LOG_LEVEL_CRITICAL) {
    g_printerr ("CRITICAL ERROR : %s\n", message);
    abort ();
  } else if (log_level & G_LOG_LEVEL_WARNING) {
    g_printerr ("WARNING : %s\n", message);
  }
}

int
LLVMFuzzerTestOneInput (const guint8 * data, size_t size)
{
  GError *err = NULL;
  GstDiscoverer *dc;
  gint timeout = 10;
  GstDiscovererInfo *info;
  static gboolean initialized = FALSE;

  if (!initialized) {
    /* We want critical warnings to assert so we can fix them */
    g_log_set_always_fatal (G_LOG_LEVEL_CRITICAL);
    g_log_set_default_handler (custom_logger, NULL);

    /* Only initialize and register plugins once */
    gst_init (NULL, NULL);

#ifndef LOCAL_FUZZ_BUILD
    GST_PLUGIN_STATIC_REGISTER (coreelements);
    GST_PLUGIN_STATIC_REGISTER (playback);
    GST_PLUGIN_STATIC_REGISTER (typefindfunctions);
    GST_PLUGIN_STATIC_REGISTER (app);
    GST_PLUGIN_STATIC_REGISTER (ogg);
    GST_PLUGIN_STATIC_REGISTER (theora);
    GST_PLUGIN_STATIC_REGISTER (vorbis);
#endif

    initialized = TRUE;
  }

  dc = gst_discoverer_new (timeout * GST_SECOND, &err);
  if (G_UNLIKELY (dc == NULL)) {
    g_print ("Error initializing: %s\n", err->message);
    g_clear_error (&err);
    exit (1);
  }

  fuzztesting_data = data;
  fuzztesting_size = size;

  /* Connect to source-setup signal to give the data */
  g_signal_connect (dc, "source-setup", (GCallback) appsrc_configuration, NULL);

  info = gst_discoverer_discover_uri (dc, "appsrc://", &err);
  g_clear_error (&err);
  if (info)
    gst_discoverer_info_unref (info);

  g_object_unref (dc);

  return 0;
}
