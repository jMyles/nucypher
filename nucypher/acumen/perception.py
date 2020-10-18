"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

import binascii
import itertools
import heapq
import random
import weakref

import maya

from bytestring_splitter import BytestringSplitter
from constant_sorrow.constants import NO_KNOWN_NODES
from collections import namedtuple, defaultdict
from collections import OrderedDict
from twisted.logger import Logger

from .nicknames import Nickname
from nucypher.crypto.api import keccak_digest


class BaseFleetState:

    def __str__(self):
        if len(ursula.known_nodes) != 0:
            # TODO: draw the icon in color, similarly to the web version?
            return '{checksum} ⇀{nickname}↽ {icon}'.format(icon=self.nickname.icon,
                                                           nickname=self.nickname,
                                                           checksum=self.checksum[:7])
        else:
            return 'No Known Nodes'


class ArchivedFleetState(BaseFleetState):

    def __init__(self, checksum, nickname, timestamp, population):
        self.checksum = checksum
        self.nickname = nickname
        self.timestamp = timestamp
        self.population = population

    def abridged_details(self):
        return {"nickname": self.nickname.payload() if self.nickname is not None else NO_KNOWN_NODES,
                "updated": self.timestamp.rfc2822()}


# Assumptions we're based on:
# - Every supplied node object, after its constructor has finished,
#   has a ``.checksum_address`` and ``bytes()`` (metadata)
# - checksum address or metadata does not change for the same Python object
# - ``this_node`` (the owner of FleetSensor) may not have a checksum address initially
#   (when the constructor is first called), but will have one at the time of the first
#   `record_fleet_state()` call. This applies to its metadata as well.
# - The metadata of ``this_node`` **can** change.
# - For the purposes of the fleet state, nodes with different metadata are considered different,
#   even if they have the same checksum address.

class FleetState(BaseFleetState):

    @classmethod
    def new(cls, this_node=None, nodes=[]):
        this_node_ref = weakref.ref(this_node) if this_node is not None else None
        # Using empty checksum so that JSON library is not confused.
        # Plus, we do need some checksum anyway. It's a legitimate state after all.
        return cls(checksum=keccak_digest(b"").hex(),
                   nodes={},
                   this_node_ref=this_node_ref,
                   this_node_metadata=None)

    def __init__(self, checksum, nodes, this_node_ref, this_node_metadata):
        self.checksum = checksum
        self.nickname = None if checksum is None else Nickname.from_seed(checksum, length=1)
        self._nodes = nodes
        self.timestamp = maya.now()
        self._this_node_ref = this_node_ref
        self._this_node_metadata = this_node_metadata

    def archived(self):
        return ArchivedFleetState(checksum=self.checksum,
                                  nickname=self.nickname,
                                  timestamp=self.timestamp,
                                  population=self.population)

    def with_updated_nodes(self, new_nodes, marked_nodes):

        # Checking if the node already has a checksum address
        # (it may be created later during the constructor)
        # or if it mutated since the last check.
        if self._this_node_ref is not None and getattr(self._this_node_ref(), 'finished_initializing', False):
            this_node = self._this_node_ref()
            this_node_metadata = bytes(this_node)
            this_node_changed = self._this_node_metadata != this_node_metadata
            this_node_list = [this_node]
        else:
            this_node_metadata = self._this_node_metadata
            this_node_changed = False
            this_node_list = []

        new_nodes = {checksum_address: node for checksum_address, node in new_nodes.items()
                     if checksum_address not in marked_nodes}

        remote_nodes_changed = (
            any(checksum_address not in self._nodes for checksum_address in new_nodes) or
            any(checksum_address in self._nodes for checksum_address in marked_nodes))

        if this_node_changed or remote_nodes_changed:
            # TODO: if nodes were kept in a Merkle tree,
            # we'd have to only recalculate log(N) checksums.
            # Is it worth it?
            nodes = dict(self._nodes)
            nodes.update(new_nodes)
            for checksum_address in marked_nodes:
                if checksum_address in nodes:
                    del nodes[checksum_address]

            all_nodes_sorted = sorted(itertools.chain(this_node_list, nodes.values()),
                                      key=lambda node: node.checksum_address)
            joined_metadata = b"".join(bytes(node) for node in all_nodes_sorted)
            checksum = keccak_digest(joined_metadata).hex()
        else:
            nodes = self._nodes
            checksum = self.checksum

        return FleetState(checksum=checksum,
                          nodes=nodes,
                          this_node_ref=self._this_node_ref,
                          this_node_metadata=this_node_metadata)

    @property
    def population(self):
        """Returns the number of all known nodes, including itself, if applicable."""
        return len(self) + int(self._this_node_metadata is not None)

    def __getitem__(self, checksum_address):
        return self._nodes[checksum_address]

    def addresses(self):
        return self._nodes.keys()

    def __bool__(self):
        return len(self) != 0

    def __contains__(self, item):
        if isinstance(item, str):
            return item in self._nodes
        else:
            return item.checksum_address in self._nodes

    def __iter__(self):
        yield from self._nodes.values()

    def __len__(self):
        return len(self._nodes)

    def snapshot(self):
        checksum_bytes = binascii.unhexlify(self.checksum)
        timestamp_bytes = self.timestamp.epoch.to_bytes(4, byteorder="big")
        return checksum_bytes + timestamp_bytes

    def shuffled(self):
        nodes_we_know_about = list(self._nodes.values())
        random.shuffle(nodes_we_know_about)
        return nodes_we_know_about

    def abridged_details(self):
        return {"nickname": str(self.nickname),
                # FIXME: generalize in case we want to extend the number of symbols in the state nickname
                "symbol": self.nickname.characters[0].symbol,
                "color_hex": self.nickname.characters[0].color_hex,
                "color_name": self.nickname.characters[0].color_name,
                "updated": self.timestamp.rfc2822(),
                }

    @property
    def icon(self) -> str:
        # FIXME: should it be called at all if there are no states recorded?
        if len(self) == 0:
            return str(NO_KNOWN_NODES)
        return self.nickname.icon

    def items(self):
        return self._nodes.items()

    def values(self):
        return self._nodes.values()

    def __repr__(self):
        return f"FleetState({self.checksum}, {self._nodes}, {self._this_node_ref}, {self._this_node_metadata})"


class FleetSensor:
    """
    A representation of a fleet of NuCypher nodes.

    If `this_node` is provided, it will be included in the state checksum
    (but not returned during iteration/lookups).
    """
    snapshot_splitter = BytestringSplitter(32, 4)
    log = Logger("Learning")

    def __init__(self, this_node=None):

        self._current_state = FleetState.new(this_node)
        self._archived_states = [self._current_state.archived()]

        # temporary accumulator for new nodes to avoid updating the fleet state every time
        self._new_nodes = {}
        self._marked = set()  # Beginning of bucketing.

        self._auto_update_state = False

    def record_node(self, node):
        self._new_nodes[node.checksum_address] = node

        if self._auto_update_state:
            self.log.info(f"Updating fleet state after saving node {node}")
            self.record_fleet_state()

    def __getitem__(self, item):
        return self._current_state[item]

    def __bool__(self):
        return bool(self._current_state)

    def __contains__(self, item):
        """
        Checks if the node *with the same metadata* is recorded in the current state.
        Does not compare ``item`` with the owner node of this FleetSensor.
        """
        return item in self._current_state

    def __iter__(self):
        yield from self._current_state

    def __len__(self):
        return len(self._current_state)

    # FIXME: is it ever used?
    def __eq__(self, other):
        raise Exception
        return self._current_state == other._current_state

    # FIXME: is it ever used?
    def __repr__(self):
        return f"FleetSensor({self._current_state.__repr__()})"

    @property
    def current_state(self):
        return self._current_state

    @property
    def checksum(self):
        # FIXME: should it be called at all if there are no states recorded?
        if self._current_state.population == 0:
            return NO_KNOWN_NODES
        return self._current_state.checksum

    @property
    def population(self):
        return self._current_state.population

    @property
    def nickname(self):
        # FIXME: should it be called at all if there are no states recorded?
        if self._current_state.population == 0:
            return NO_KNOWN_NODES
        return self._current_state.nickname

    @property
    def icon(self) -> str:
        # FIXME: should it be called at all if there are no states recorded?
        return self._current_state.icon

    @property
    def timestamp(self):
        return self._current_state.timestamp

    def items(self):
        return self._current_state.items()

    def values(self):
        return self._current_state.values()

    def latest_states(self, quantity):
        # the last archived state is the current state
        return self._archived_states[-min(len(self._archived_states) - 1, quantity):-1]

    def addresses(self):
        return self._current_state.addresses()

    def snapshot(self):
        return self._current_state.snapshot()

    def record_fleet_state(self):
        new_state = self._current_state.with_updated_nodes(self._new_nodes, self._marked)
        self._new_nodes = {}
        self._marked = set()
        self._current_state = new_state

        # TODO: set a limit on the number of archived states?
        # Two ways to collect archived states:
        # 1. (current) add a state to the archive every time it changes
        # 2. (possible) keep a dictionary of known states
        #    and bump the timestamp of a previously encountered one
        if new_state.checksum != self._archived_states[-1].checksum:
            self._archived_states.append(new_state.archived())

    def shuffled(self):
        return self._current_state.shuffled()

    def abridged_states_dict(self):
        abridged_states = {}
        for state in self._archived_states:
            abridged_states[state.checksum] = state.abridged_details()
        abridged_states[self._current_state.checksum] = self._current_state.abridged_details()
        return abridged_states

    def mark_as(self, label: Exception, node: "Teacher"):
        # TODO: for now we're not using `label` in any way, so we're just ignoring it
        self._marked.add(node.checksum_address)
