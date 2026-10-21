using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The consecutive failed keepalives, each of which reached the network, after which a punched route is dropped.</summary>
        private const int KeepAliveFailureLimit = 2;
        /// <summary>The loop that keeps punched routes open while they are idle.</summary>
        private Task _routeKeepAlive = Task.CompletedTask;

        /// <summary>Checks whether this node holds an unexpired punched route to a peer over one transport.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <param name="transport">The transport of the route.</param>
        /// <returns>Whether such a route is retained.</returns>
        internal bool HasDirectRoute(string nodeId, DHTTransport transport)
        {
            lock (_gate)
            {
                return _directRoutes.TryGetValue((nodeId, transport), out var route) && route.ExpiresAt > DateTimeOffset.UtcNow;
            }
        }

        /// <summary>Starts the keepalive loop of punched routes, which only exist while NAT traversal is enabled.</summary>
        /// <remarks>The caller starts the node and calls this once.</remarks>
        private void StartRouteKeepAlive()
        {
            if (_options.EnableNatTraversal)
            {
                _routeKeepAlive = KeepDirectRoutesAliveAsync();
            }
        }

        /// <summary>
        /// Wakes every half <see cref="DHTNodeOptions.NatKeepAliveInterval"/> and pings each punched route that has carried no
        /// successful exchange for at least half an interval, most idle first. NAT mappings, stateful firewalls and TCP sessions
        /// expire after a period without traffic, and the peer behind them can then only be reached by punching again; a route
        /// therefore never stays idle much longer than one interval. Routes in use are not pinged.
        /// </summary>
        /// <returns>Completion after node shutdown, once every started keepalive has finished.</returns>
        private async Task KeepDirectRoutesAliveAsync()
        {
            var tick = TimeSpan.FromTicks(_options.NatKeepAliveInterval.Ticks / 2);
            var pending = new List<Task>();
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    await Task.Delay(tick, _lifetime.Token).ConfigureAwait(false);
                    pending.RemoveAll(work => work.IsCompleted);
                    foreach (var due in ClaimIdleDirectRoutes(tick))
                    {
                        pending.Add(KeepDirectRouteAliveAsync(due.Key, due.Route));
                    }
                }
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Direct route keepalive loop stopped: ", exception);
            }
            finally
            {
                // Every keepalive observes its own failures, so waiting here only drains them before shutdown completes.
                await Task.WhenAll(pending).ConfigureAwait(false);
            }
        }

        /// <summary>Marks every unexpired punched route that has been idle for at least the given time and has no keepalive in flight.</summary>
        /// <param name="idle">The minimum idle time of a route to ping.</param>
        /// <returns>The claimed routes, most idle first, so that the outgoing exchange limit admits the most urgent ones.</returns>
        private List<((string, DHTTransport) Key, DirectRoute Route)> ClaimIdleDirectRoutes(TimeSpan idle)
        {
            var due = new List<((string, DHTTransport) Key, DirectRoute Route)>();
            lock (_gate)
            {
                var now = DateTimeOffset.UtcNow;
                foreach (var entry in _directRoutes)
                {
                    var route = entry.Value;
                    if (!route.KeepAliveInFlight && route.ExpiresAt > now && now - route.LastActivity >= idle)
                    {
                        route.KeepAliveInFlight = true;
                        due.Add((entry.Key, route));
                    }
                }
            }
            due.Sort((left, right) => left.Route.LastActivity.CompareTo(right.Route.LastActivity));
            return due;
        }

        /// <summary>
        /// Sends one authenticated Ping over a punched route. Its request and response pass every NAT and firewall on the route
        /// in both directions and, over TCP, renew the punched session's idle lifetime at both ends. A Ping that fails after
        /// reaching the network counts against the route, which is dropped after <see cref="KeepAliveFailureLimit"/> consecutive
        /// failures so that the next request falls back to an assisted route at once; a Ping that this node could not even send,
        /// because its outgoing exchange limit was reached, does not count.
        /// </summary>
        /// <param name="key">The peer and transport of the route.</param>
        /// <param name="route">The claimed route.</param>
        /// <returns>Completion after the route state was updated; failures are logged, never thrown.</returns>
        private async Task KeepDirectRouteAliveAsync((string, DHTTransport) key, DirectRoute route)
        {
            var transport = key.Item2;
            var counter = new TransmissionCounter();
            var succeeded = false;
            try
            {
                var request = new Packet(LocalContact, Crypto.Random(16), (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty);
                var encoded = await _transport.ExchangeAtAsync(transport, route.Endpoint, request.Seal(_identity, route.Peer), _lifetime.Token, counter)
                    .ConfigureAwait(false);
                using var response = AuthenticateResponse(encoded, route.Peer, request);
                ResponseStatus.ReadResult(response.Packet.Body);
                succeeded = true;
            }
            catch (Exception exception) when (IsPeerFailure(exception) || exception is OperationCanceledException || exception is ObjectDisposedException)
            {
                if (!_lifetime.IsCancellationRequested)
                {
                    Log(LogLevel.Debug, "Direct route keepalive failed: ", exception);
                }
            }
            finally
            {
                RecordTransmissions(route.Peer.NodeId, transport, route.Endpoint, counter);
            }
            lock (_gate)
            {
                route.KeepAliveInFlight = false;
                if (succeeded)
                {
                    route.KeepAliveFailures = 0;
                    route.MarkActive();
                    return;
                }
                if (counter.Sent == 0 || _lifetime.IsCancellationRequested)
                {
                    return;
                }
                route.KeepAliveFailures++;
                if (route.KeepAliveFailures < KeepAliveFailureLimit || !_directRoutes.TryGetValue(key, out var current) || !ReferenceEquals(current, route))
                {
                    return;
                }
                _directRoutes.Remove(key);
            }
            Log(LogLevel.Information, transport == DHTTransport.Tcp
                ? "Dropped a punched TCP route that stopped answering keepalives."
                : "Dropped a punched UDP route that stopped answering keepalives.");
        }

        /// <summary>
        /// An authenticated punched route to a peer: the endpoint that answered, its retention deadline and the state of the
        /// keepalive that holds the NAT mappings along it open.
        /// </summary>
        private sealed class DirectRoute
        {
            /// <summary>The time of the latest successful exchange over the route, in UTC ticks.</summary>
            private long _lastActivity;

            /// <summary>Gets the authenticated peer contact that keepalive requests are sealed to.</summary>
            internal DHTContact Peer { get; }
            /// <summary>Gets the privately owned endpoint of the route.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the retention deadline, bounded by the peer's contact lease.</summary>
            internal DateTimeOffset ExpiresAt { get; }
            /// <summary>Gets the time of the latest successful exchange over the route.</summary>
            internal DateTimeOffset LastActivity => new DateTimeOffset(Interlocked.Read(ref _lastActivity), TimeSpan.Zero);
            /// <summary>Gets or sets whether a keepalive is in flight; guarded by the node state lock.</summary>
            internal bool KeepAliveInFlight { get; set; }
            /// <summary>Gets or sets the consecutive failed keepalives that reached the network; guarded by the node state lock.</summary>
            internal int KeepAliveFailures { get; set; }

            /// <summary>Creates a route that has just been authenticated by a punch.</summary>
            /// <param name="peer">The authenticated peer contact.</param>
            /// <param name="endpoint">The privately owned endpoint.</param>
            /// <param name="expiresAt">The retention deadline.</param>
            internal DirectRoute(DHTContact peer, IPEndPoint endpoint, DateTimeOffset expiresAt)
            {
                Peer = peer;
                Endpoint = endpoint;
                ExpiresAt = expiresAt;
                _lastActivity = DateTimeOffset.UtcNow.UtcTicks;
            }

            /// <summary>Records a successful exchange, which refreshed the NAT state along the route.</summary>
            internal void MarkActive()
            {
                Interlocked.Exchange(ref _lastActivity, DateTimeOffset.UtcNow.UtcTicks);
            }
        }
    }
}
