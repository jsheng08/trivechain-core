#!/usr/bin/env python3
# Copyright (c) 2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import DashTestFramework
from test_framework.util import *
from time import *

'''
p2p-autodirectsend.py

Test automatic DirectSend locks functionality.

Checks that simple transactions automatically become DirectSend locked, 
complex transactions don't become IS-locked and this functionality is
activated only if SPORK_16_DIRECTSEND_AUTOLOCKS is active.

Also checks that this functionality doesn't influence regular DirectSend
transactions with high fee. 
'''

class AutoDirectSendTest(DashTestFramework):
    def __init__(self):
        super().__init__(8, 5, [], fast_dip3_enforcement=True)
        # set sender,  receiver,  isolated nodes
        self.receiver_idx = 1
        self.sender_idx = 2

    def run_test(self):
        # make sure masternodes are synced
        sync_masternodes(self.nodes)

        self.nodes[0].spork("SPORK_17_QUORUM_DKG_ENABLED", 0)
        self.wait_for_sporks_same()
        self.mine_quorum()

        self.log.info("Test old DirectSend")
        self.test_auto();

        # Generate 6 block to avoid retroactive signing overloading Travis
        self.nodes[0].generate(6)
        sync_blocks(self.nodes)

        self.nodes[0].spork("SPORK_20_DIRECTSEND_LLMQ_BASED", 0)
        self.wait_for_sporks_same()

        self.log.info("Test new DirectSend")
        self.test_auto(True);

    def test_auto(self, new_is = False):
        sender = self.nodes[self.sender_idx]
        receiver = self.nodes[self.receiver_idx]
        # feed the sender with some balance, make sure there are enough inputs
        recipients = {}
        for i in range(0, 30):
            recipients[sender.getnewaddress()] = 1
        # use a single transaction to not overload Travis with DirectSend
        self.nodes[0].sendmany("", recipients)

        # make sender funds mature for DirectSend
        for i in range(0, 2):
            set_mocktime(get_mocktime() + 1)
            set_node_times(self.nodes, get_mocktime())
            self.nodes[0].generate(1)
        self.sync_all()

        assert(not self.get_autois_spork_state(self.nodes[0]))

        assert(self.send_regular_directsend(sender, receiver, not new_is))
        assert(self.send_simple_tx(sender, receiver) if new_is else not self.send_simple_tx(sender, receiver))
        assert(self.send_complex_tx(sender, receiver) if new_is else not self.send_complex_tx(sender, receiver))

        self.activate_autois_bip9(self.nodes[0])
        self.set_autois_spork_state(self.nodes[0], True)

        assert(self.get_autois_bip9_status(self.nodes[0]) == 'active')
        assert(self.get_autois_spork_state(self.nodes[0]))

        assert(self.send_regular_directsend(sender, receiver, not new_is))
        assert(self.send_simple_tx(sender, receiver))
        assert(self.send_complex_tx(sender, receiver) if new_is else not self.send_complex_tx(sender, receiver))

        self.set_autois_spork_state(self.nodes[0], False)
        assert(not self.get_autois_spork_state(self.nodes[0]))

        assert(self.send_regular_directsend(sender, receiver, not new_is))
        assert(self.send_simple_tx(sender, receiver) if new_is else not self.send_simple_tx(sender, receiver))
        assert(self.send_complex_tx(sender, receiver) if new_is else not self.send_complex_tx(sender, receiver))

        # mine all mempool txes
        set_mocktime(get_mocktime() + 1)
        set_node_times(self.nodes, get_mocktime())
        self.nodes[0].generate(1)
        self.sync_all()

if __name__ == '__main__':
    AutoDirectSendTest().main()
