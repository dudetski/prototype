import random
import logging
import time
import threading
from typing import Dict, List, Optional, Set, Callable

logger = logging.getLogger(__name__)

class GossipProtocol:
    def __init__(self, reliability=0.95, sync_interval=60, message_ttl=300):
        """
        Initializes the gossip protocol.
        
        Args:
            reliability: Probability of successful message delivery (0.0-1.0)
            sync_interval: Time between automatic synchronization attempts (seconds)
            message_ttl: Time-to-live for messages (seconds)
        """
        self.agents = {}  # agent_id -> agent
        self.message_cache = {}  # message_id -> (message, timestamp)
        self.reliability = reliability
        self.sync_interval = sync_interval
        self.message_ttl = message_ttl
        self.transport = None
        self.running = False
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "delivery_failures": 0
        }
        self.sync_thread = None
        self.message_listeners = []  # callback functions for message monitoring
        self.cache_lock = threading.Lock()  # Lock for thread-safe cache operations
    
    def start(self):
        """
        Starts the gossip protocol service.
        """
        self.running = True
        
        # Start message cache cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        # Start periodic sync thread
        if self.sync_interval > 0:
            self.sync_thread = threading.Thread(target=self._periodic_sync)
            self.sync_thread.daemon = True
            self.sync_thread.start()
        
        logger.info("Gossip protocol service started")
    
    def stop(self):
        """
        Stops the gossip protocol service.
        """
        self.running = False
        logger.info("Gossip protocol service stopped")
    
    def register_agent(self, agent):
        """
        Registers an agent with the gossip protocol.
        
        Args:
            agent: The agent to register
        """
        self.agents[agent.agent_id] = agent
        logger.info(f"Agent {agent.agent_id} registered with gossip protocol")
    
    def unregister_agent(self, agent_id):
        """
        Unregisters an agent from the gossip protocol.
        
        Args:
            agent_id: ID of the agent to unregister
        """
        if agent_id in self.agents:
            del self.agents[agent_id]
            logger.info(f"Agent {agent_id} unregistered from gossip protocol")
    
    def broadcast(self, message):
        """
        Broadcasts a message to all agents.
        
        Args:
            message: The message to broadcast
        """
        with self.cache_lock:
            self.message_cache[message.message_id] = (message, time.time())
        
        logger.info(f"Broadcasting message from {message.sender_id}: {message.msg_type}")
        self.stats["messages_sent"] += 1
        
        # Notify message listeners
        for listener in self.message_listeners:
            try:
                listener("broadcast", message)
            except Exception as e:
                logger.error(f"Error in message listener: {e}")
        
        for agent_id, agent in self.agents.items():
            if agent_id != message.sender_id:
                if random.random() < self.reliability:
                    try:
                        agent.receive_message(message)
                    except Exception as e:
                        logger.error(f"Error delivering message to agent {agent_id}: {e}")
                        self.stats["delivery_failures"] += 1
                else:
                    logger.warning(f"Simulated delivery failure from {message.sender_id} to {agent_id}")
                    self.stats["delivery_failures"] += 1
        
        # If connected to a network transport, broadcast to external network
        if hasattr(self, 'transport') and self.transport:
            self.transport.broadcast_to_network(message)
    
    def send_message(self, message, recipient_id):
        """
        Sends a message to a specific agent.
        
        Args:
            message: The message to send
            recipient_id: ID of the recipient agent
        
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        with self.cache_lock:
            self.message_cache[message.message_id] = (message, time.time())
        
        if recipient_id not in self.agents:
            logger.error(f"Error sending message: agent {recipient_id} not found")
            return False
        
        logger.info(f"Sending message from {message.sender_id} to {recipient_id}: {message.msg_type}")
        self.stats["messages_sent"] += 1
        
        # Notify message listeners
        for listener in self.message_listeners:
            try:
                listener("direct", message, recipient_id)
            except Exception as e:
                logger.error(f"Error in message listener: {e}")
        
        if random.random() < self.reliability:
            try:
                self.agents[recipient_id].receive_message(message)
                return True
            except Exception as e:
                logger.error(f"Error delivering message to agent {recipient_id}: {e}")
                self.stats["delivery_failures"] += 1
                return False
        else:
            logger.warning(f"Simulated delivery failure from {message.sender_id} to {recipient_id}")
            self.stats["delivery_failures"] += 1
            return False
    
    def get_random_peers(self, agent_id, count=3):
        """
        Gets a random subset of peers for an agent.
        
        Args:
            agent_id: ID of the agent
            count: Number of peers to return
        
        Returns:
            list: List of peer agent IDs
        """
        peers = [pid for pid in self.agents.keys() if pid != agent_id]
        if len(peers) <= count:
            return peers
        return random.sample(peers, count)
    
    def gossip_sync(self, agent_id):
        """
        Initiates a gossip synchronization for an agent.
        
        Args:
            agent_id: ID of the agent initiating sync
        """
        if agent_id not in self.agents:
            logger.error(f"Error syncing: agent {agent_id} not found")
            return
        
        peers = self.get_random_peers(agent_id)
        if not peers:
            logger.warning(f"Agent {agent_id} has no peers for synchronization")
            return
        
        for peer_id in peers:
            try:
                request = Message(agent_id, {"type": "SYNC_REQUEST"}, "SYNC")
                request.signature = self.agents[agent_id].sign_message(
                    request.to_string(), self.agents[agent_id].private_key
                )
                self.send_message(request, peer_id)
                logger.info(f"Synchronization request from {agent_id} to {peer_id}")
            except Exception as e:
                logger.error(f"Error sending sync request from {agent_id} to {peer_id}: {e}")
    
    def connect_to_network_transport(self, transport):
        """
        Connects the gossip protocol to a network transport.
        
        Args:
            transport: The network transport to connect to
        """
        self.transport = transport
        transport.gossip = self
        logger.info("Gossip protocol connected to network transport")
    
    def process_remote_message(self, message):
        """
        Processes a message received from the remote network.
        
        Args:
            message: The message to process
        """
        logger.info(f"Received remote message from {message.sender_id}: {message.msg_type}")
        
        with self.cache_lock:
            if message.message_id in self.message_cache:
                logger.debug(f"Duplicate message {message.message_id} ignored")
                return
            
            self.message_cache[message.message_id] = (message, time.time())
        
        self.stats["messages_received"] += 1
        
        # Notify message listeners
        for listener in self.message_listeners:
            try:
                listener("remote", message)
            except Exception as e:
                logger.error(f"Error in message listener: {e}")
        
        for agent_id, agent in self.agents.items():
            try:
                agent.receive_message(message)
            except Exception as e:
                logger.error(f"Error delivering remote message to agent {agent_id}: {e}")
    
    def add_message_listener(self, listener):
        """
        Adds a message listener function.
        
        Args:
            listener: Callback function(msg_type, message, recipient=None)
        """
        self.message_listeners.append(listener)
    
    def get_stats(self):
        """
        Gets protocol statistics.
        
        Returns:
            dict: Dictionary with protocol statistics
        """
        return {
            **self.stats,
            "cached_messages": len(self.message_cache),
            "registered_agents": len(self.agents),
            "reliability": self.reliability
        }
    
    def _cleanup_thread(self):
        """
        Thread to periodically clean up expired messages.
        """
        while self.running:
            time.sleep(60)  # Check every minute
            self._cleanup_message_cache()
    
    def _cleanup_message_cache(self):
        """
        Removes expired messages from the message cache.
        """
        now = time.time()
        with self.cache_lock:
            expired_ids = [msg_id for msg_id, (_, timestamp) in self.message_cache.items()
                          if now - timestamp > self.message_ttl]
            
            for msg_id in expired_ids:
                del self.message_cache[msg_id]
            
            if expired_ids:
                logger.debug(f"Cleaned up {len(expired_ids)} expired messages")
    
    def _periodic_sync(self):
        """
        Thread to periodically trigger gossip synchronization.
        """
        while self.running:
            time.sleep(self.sync_interval)
            
            # Select a random subset of agents to initiate gossip
            if self.agents:
                sync_agents = random.sample(
                    list(self.agents.keys()),
                    min(3, len(self.agents))
                )
                
                for agent_id in sync_agents:
                    self.gossip_sync(agent_id)