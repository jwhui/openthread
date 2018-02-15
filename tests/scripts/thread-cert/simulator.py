#!/usr/bin/env python
#
#  Copyright (c) 2018, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

import bisect
import cmd
import os
import socket
import struct
import time
import sys

import io
import config
import message

class RealTime:

    def __init__(self):
        self._sniffer = config.create_default_thread_sniffer()
        self._sniffer.start()

    def set_lowpan_context(self, cid, prefix):
        self._sniffer.set_lowpan_context(cid, prefix)

    def get_messages_sent_by(self, nodeid):
        return self._sniffer.get_messages_sent_by(nodeid)

    def go(self, duration):
        time.sleep(duration)

class VirtualTime:

    BASE_PORT = 9000
    MAX_NODES = 34
    PORT_OFFSET = int(os.getenv('PORT_OFFSET', "0"))

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        ip = '127.0.0.1'
        self._port = self.BASE_PORT + (self.PORT_OFFSET * self.MAX_NODES)
        self._sock.bind((ip, self._port))

        self._devices = {}
        self._event_queue = []
        self._event_count = 0
        self._current_time = 0
        self._current_event = None;

        self._message_factory = config.create_default_thread_message_factory()

    def __del__(self):
        self._sock.close()

    def _add_message(self, nodeid, message):
        addr = ('127.0.0.1', self._port + nodeid)

        # Ignore any exceptions
        try:
            msg = self._message_factory.create(io.BytesIO(message))

            if msg is not None:
                self._devices[addr]['msgs'].append(msg)

        except Exception as e:
            # Just print the exception to the console
            print("EXCEPTION: %s" % e)
            pass

    def _add_alarm(self, event):
        addr = event[1]

        # remove any existing alarm event for device
        try:
            self._event_queue.remove(self._devices[addr]['alarm'])
            #print "-- Remove\t", self._devices[addr]['alarm']
            self._devices[addr]['alarm'] = None
        except ValueError:
            pass

        # add alarm event to event queue
        bisect.insort(self._event_queue, event)
        self._devices[addr]['alarm'] = event

    def set_lowpan_context(self, cid, prefix):
        self._message_factory.set_lowpan_context(cid, prefix)

    def get_messages_sent_by(self, nodeid):
        """ Get sniffed messages.

        Note! This method flushes the message queue so calling this method again will return only the newly logged messages.

        Args:
            nodeid (int): node id

        Returns:
            MessagesSet: a set with received messages.
        """
        addr = ('127.0.0.1', self._port + nodeid)

        messages = self._devices[addr]['msgs']
        self._devices[addr]['msgs'] = []

        return message.MessagesSet(messages)

    def receive_events(self):

        if self._current_event is None:
            self._sock.setblocking(0)
        else:
            self._sock.setblocking(1)

        while True:
            try:
                msg, addr = self._sock.recvfrom(1024)
            except socket.error:
                break

            if addr not in self._devices:
                self._devices[addr] = {}
                self._devices[addr]['alarm'] = None
                self._devices[addr]['msgs'] = []
                self._devices[addr]['time'] = self._current_time
                #print "New device:", addr, self._devices

            delay, type, datalen = struct.unpack('=QBH', msg[:11])
            data = msg[11:]

            event_time = self._current_time + delay

            if type == 0:
                event = (event_time, addr, type, datalen)
                self._add_alarm(event)

                if self._current_event is not None and self._current_event[1] == addr:
                    #print "Done\t", self._current_event
                    self._current_event = None
                    return

            elif type == 1:
                # add radio receive events event queue
                for device in self._devices:
                    if device != addr:
                        event = (event_time, device, type, datalen, data)
                        #print "-- Enqueue\t", event
                        bisect.insort(self._event_queue, event)

                self._add_message(addr[1] - self._port, data)

                # add radio transmit done events to event queue
                event = (event_time, addr, type, datalen, data)
                bisect.insort(self._event_queue, event)

    def _process_next_event(self):

        assert(self._current_event == None)

        #print "Events", len(self._event_queue)
        count = 0
        for event in self._event_queue:
            #print count, event
            count += 1

        # process next event
        try:
            event = self._event_queue.pop(0)
        except IndexError:
            return

        #print "Pop\t", event

        if len(event) == 4:
            event_time, addr, type, datalen = event
        else:
            event_time, addr, type, datalen, data = event

        self._event_count += 1
        self._current_event = event

        assert(event_time >= self._current_time)
        self._current_time = event_time

        elapsed = event_time - self._devices[addr]['time']
        self._devices[addr]['time'] = event_time

        message = struct.pack('=QBH', elapsed, type, datalen)

        if type == 0:
            self._devices[addr]['alarm'] = None
            rval = self._sock.sendto(message, addr)
            assert(rval == len(message))
        elif type == 1:
            message += data
            rval = self._sock.sendto(message, addr)
            assert(rval == len(message))

    def _sync_time(self):
        sync_time = self._current_time

        for addr in self._devices:
            event = (sync_time, addr, 0, 0)
            self._add_alarm(event)

        while self._event_queue[0][0] <= sync_time:
            self._process_next_event()
            self.receive_events()

        for addr in self._devices:
            assert(self._devices[addr]['time'] == sync_time)

    def go(self, duration):

        print "running for %d s" % duration

        self.receive_events()

        duration = int(duration) * 1000000
        end_time = self._current_time + duration

        while self._current_time <= end_time:
            self._process_next_event()
            self.receive_events()

        self._sync_time()
