/* Asynchronous replication implementation.
 *
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include "server.h"

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

void replicationDiscardCachedMaster(void);
void replicationResurrectCachedMaster(int newfd);
void replicationSendAck(void);
void putSlaveOnline(client *slave);
int cancelReplicationHandshake(void);

/* --------------------------- Utility functions ---------------------------- */

/* Return the pointer to a string representing the slave ip:listening_port
 * pair. Mostly useful for logging, since we want to log a slave using its
 * IP address and it's listening port which is more clear for the user, for
 * example: "Closing connection with slave 10.1.2.3:6380". */
char *replicationGetSlaveName(client *c) {
    static char buf[NET_PEER_ID_LEN];
    char ip[NET_IP_STR_LEN];

    ip[0] = '\0';
    buf[0] = '\0';
    if (anetPeerToString(c->fd,ip,sizeof(ip),NULL) != -1) {
        if (c->slave_listening_port)
            anetFormatAddr(buf,sizeof(buf),ip,c->slave_listening_port);
        else
            snprintf(buf,sizeof(buf),"%s:<unknown-slave-port>",ip);
    } else {
        snprintf(buf,sizeof(buf),"client id #%llu",
            (unsigned long long) c->id);
    }
    return buf;
}

/* ---------------------------------- MASTER -------------------------------- */

//针对master，创建backlog

void createReplicationBacklog(void) {
    serverAssert(server.repl_backlog == NULL);
    server.repl_backlog = zmalloc(server.repl_backlog_size);
    server.repl_backlog_histlen = 0;
    server.repl_backlog_idx = 0;
    /* When a new backlog buffer is created, we increment the replication
     * offset by one to make sure we'll not be able to PSYNC with any
     * previous slave. This is needed because we avoid incrementing the
     * master_repl_offset if no backlog exists nor slaves are attached. */
    server.master_repl_offset++;

    /* We don't have any data inside our buffer, but virtually the first
     * byte we have is the next byte that will be generated for the
     * replication stream. */
    server.repl_backlog_off = server.master_repl_offset+1;
}


/* This function is called when the user modifies the replication backlog
 * size at runtime. It is up to the function to both update the
 * server.repl_backlog_size and to resize the buffer and setup it so that
 * it contains the same data as the previous one (possibly less data, but
 * the most recent bytes, or the same data and more free space in case the
 * buffer is enlarged). */
void resizeReplicationBacklog(long long newsize) {
    if (newsize < CONFIG_REPL_BACKLOG_MIN_SIZE)
        newsize = CONFIG_REPL_BACKLOG_MIN_SIZE;
    if (server.repl_backlog_size == newsize) return;

    server.repl_backlog_size = newsize;
    if (server.repl_backlog != NULL) {
        /* What we actually do is to flush the old buffer and realloc a new
         * empty one. It will refill with new data incrementally.
         * The reason is that copying a few gigabytes adds latency and even
         * worse often we need to alloc additional space before freeing the
         * old buffer. */
        zfree(server.repl_backlog);
        server.repl_backlog = zmalloc(server.repl_backlog_size);
        server.repl_backlog_histlen = 0;
        server.repl_backlog_idx = 0;
        /* Next byte we have is... the next since the buffer is empty. */
        server.repl_backlog_off = server.master_repl_offset+1;
    }
}

void freeReplicationBacklog(void) {
    serverAssert(listLength(server.slaves) == 0);
    zfree(server.repl_backlog);
    server.repl_backlog = NULL;
}

/* Add data to the replication backlog.
 * This function also increments the global replication offset stored at
 * server.master_repl_offset, because there is no case where we want to feed
 * the backlog without incrementing the buffer. */
void feedReplicationBacklog(void *ptr, size_t len) {
    unsigned char *p = ptr;

    server.master_repl_offset += len;

    /* This is a circular buffer, so write as much data we can at every
     * iteration and rewind the "idx" index if we reach the limit. */
    while(len) {
        size_t thislen = server.repl_backlog_size - server.repl_backlog_idx;
        if (thislen > len) thislen = len;
        memcpy(server.repl_backlog+server.repl_backlog_idx,p,thislen);
        server.repl_backlog_idx += thislen;
        if (server.repl_backlog_idx == server.repl_backlog_size)
            server.repl_backlog_idx = 0;
        len -= thislen;
        p += thislen;
        server.repl_backlog_histlen += thislen;
    }
    if (server.repl_backlog_histlen > server.repl_backlog_size)
        server.repl_backlog_histlen = server.repl_backlog_size;
    /* Set the offset of the first byte we have in the backlog. */
    server.repl_backlog_off = server.master_repl_offset -
                              server.repl_backlog_histlen + 1;
}

/* Wrapper for feedReplicationBacklog() that takes Redis string objects
 * as input. */
void feedReplicationBacklogWithObject(robj *o) {
    char llstr[LONG_STR_SIZE];
    void *p;
    size_t len;

    if (o->encoding == OBJ_ENCODING_INT) {
        len = ll2string(llstr,sizeof(llstr),(long)o->ptr);
        p = llstr;
    } else {
        len = sdslen(o->ptr);
        p = o->ptr;
    }
    feedReplicationBacklog(p,len);
}

void replicationFeedSlaves(list *slaves, int dictid, robj **argv, int argc) {
    listNode *ln;
    listIter li;
    int j, len;
    char llstr[LONG_STR_SIZE];

    /* If there aren't slaves, and there is no backlog buffer to populate,
     * we can return ASAP. */
    if (server.repl_backlog == NULL && listLength(slaves) == 0) return;

    /* We can't have slaves attached and no backlog. */
    serverAssert(!(listLength(slaves) != 0 && server.repl_backlog == NULL));

    /* Send SELECT command to every slave if needed. */
    if (server.slaveseldb != dictid) {
        robj *selectcmd;

        /* For a few DBs we have pre-computed SELECT command. */
        if (dictid >= 0 && dictid < PROTO_SHARED_SELECT_CMDS) {
            selectcmd = shared.select[dictid];
        } else {
            int dictid_len;

            dictid_len = ll2string(llstr,sizeof(llstr),dictid);
            selectcmd = createObject(OBJ_STRING,
                sdscatprintf(sdsempty(),
                "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
                dictid_len, llstr));
        }

        /* Add the SELECT command into the backlog. */
        if (server.repl_backlog) feedReplicationBacklogWithObject(selectcmd);

        /* Send it to slaves. */
        listRewind(slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;
            addReply(slave,selectcmd);
        }

        if (dictid < 0 || dictid >= PROTO_SHARED_SELECT_CMDS)
            decrRefCount(selectcmd);
    }
    server.slaveseldb = dictid;

    /* Write the command to the replication backlog if any. */
    if (server.repl_backlog) {
        char aux[LONG_STR_SIZE+3];

        /* Add the multi bulk reply length. */
        aux[0] = '*';
        len = ll2string(aux+1,sizeof(aux)-1,argc);
        aux[len+1] = '\r';
        aux[len+2] = '\n';
        feedReplicationBacklog(aux,len+3);

        for (j = 0; j < argc; j++) {
            long objlen = stringObjectLen(argv[j]);

            /* We need to feed the buffer with the object as a bulk reply
             * not just as a plain string, so create the $..CRLF payload len
             * and add the final CRLF */
            aux[0] = '$';
            len = ll2string(aux+1,sizeof(aux)-1,objlen);
            aux[len+1] = '\r';
            aux[len+2] = '\n';
            feedReplicationBacklog(aux,len+3);
            feedReplicationBacklogWithObject(argv[j]);
            feedReplicationBacklog(aux+len+1,2);
        }
    }

    /* Write the command to every slave. */
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        /* Don't feed slaves that are still waiting for BGSAVE to start */
        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;

        /* Feed slaves that are waiting for the initial SYNC (so these commands
         * are queued in the output buffer until the initial SYNC completes),
         * or are already in sync with the master. */

        /* Add the multi bulk length. */
        addReplyMultiBulkLen(slave,argc);

        /* Finally any additional argument that was not stored inside the
         * static buffer if any (from j to argc). */
        for (j = 0; j < argc; j++)
            addReplyBulk(slave,argv[j]);
    }
}

void replicationFeedMonitors(client *c, list *monitors, int dictid, robj **argv, int argc) {
    listNode *ln;
    listIter li;
    int j;
    sds cmdrepr = sdsnew("+");
    robj *cmdobj;
    struct timeval tv;

    gettimeofday(&tv,NULL);
    cmdrepr = sdscatprintf(cmdrepr,"%ld.%06ld ",(long)tv.tv_sec,(long)tv.tv_usec);
    if (c->flags & CLIENT_LUA) {
        cmdrepr = sdscatprintf(cmdrepr,"[%d lua] ",dictid);
    } else if (c->flags & CLIENT_UNIX_SOCKET) {
        cmdrepr = sdscatprintf(cmdrepr,"[%d unix:%s] ",dictid,server.unixsocket);
    } else {
        cmdrepr = sdscatprintf(cmdrepr,"[%d %s] ",dictid,getClientPeerId(c));
    }

    for (j = 0; j < argc; j++) {
        if (argv[j]->encoding == OBJ_ENCODING_INT) {
            cmdrepr = sdscatprintf(cmdrepr, "\"%ld\"", (long)argv[j]->ptr);
        } else {
            cmdrepr = sdscatrepr(cmdrepr,(char*)argv[j]->ptr,
                        sdslen(argv[j]->ptr));
        }
        if (j != argc-1)
            cmdrepr = sdscatlen(cmdrepr," ",1);
    }
    cmdrepr = sdscatlen(cmdrepr,"\r\n",2);
    cmdobj = createObject(OBJ_STRING,cmdrepr);

    listRewind(monitors,&li);
    while((ln = listNext(&li))) {
        client *monitor = ln->value;
        addReply(monitor,cmdobj);
    }
    decrRefCount(cmdobj);
}

/* Feed the slave 'c' with the replication backlog starting from the
 * specified 'offset' up to the end of the backlog. */
long long addReplyReplicationBacklog(client *c, long long offset) {
    long long j, skip, len;

    serverLog(LL_DEBUG, "[PSYNC] Slave request offset: %lld", offset);

    if (server.repl_backlog_histlen == 0) {
        serverLog(LL_DEBUG, "[PSYNC] Backlog history len is zero");
        return 0;
    }

    serverLog(LL_DEBUG, "[PSYNC] Backlog size: %lld",
             server.repl_backlog_size);
    serverLog(LL_DEBUG, "[PSYNC] First byte: %lld",
             server.repl_backlog_off);
    serverLog(LL_DEBUG, "[PSYNC] History len: %lld",
             server.repl_backlog_histlen);
    serverLog(LL_DEBUG, "[PSYNC] Current index: %lld",
             server.repl_backlog_idx);

    /* Compute the amount of bytes we need to discard. */
    skip = offset - server.repl_backlog_off;
    serverLog(LL_DEBUG, "[PSYNC] Skipping: %lld", skip);

    /* Point j to the oldest byte, that is actaully our
     * server.repl_backlog_off byte. */
    j = (server.repl_backlog_idx +
        (server.repl_backlog_size-server.repl_backlog_histlen)) %
        server.repl_backlog_size;
    serverLog(LL_DEBUG, "[PSYNC] Index of first byte: %lld", j);

    /* Discard the amount of data to seek to the specified 'offset'. */
    j = (j + skip) % server.repl_backlog_size;

    /* Feed slave with data. Since it is a circular buffer we have to
     * split the reply in two parts if we are cross-boundary. */
    len = server.repl_backlog_histlen - skip;
    serverLog(LL_DEBUG, "[PSYNC] Reply total length: %lld", len);
    while(len) {
        long long thislen =
            ((server.repl_backlog_size - j) < len) ?
            (server.repl_backlog_size - j) : len;

        serverLog(LL_DEBUG, "[PSYNC] addReply() length: %lld", thislen);
        addReplySds(c,sdsnewlen(server.repl_backlog + j, thislen));
        len -= thislen;
        j = 0;
    }
    return server.repl_backlog_histlen - skip;
}

/* Return the offset to provide as reply to the PSYNC command received
 * from the slave. The returned value is only valid immediately after
 * the BGSAVE process started and before executing any other command
 * from clients. */
long long getPsyncInitialOffset(void) {
    long long psync_offset = server.master_repl_offset;
    /* Add 1 to psync_offset if it the replication backlog does not exists
     * as when it will be created later we'll increment the offset by one. */
    if (server.repl_backlog == NULL) psync_offset++;
    return psync_offset;
}

/* Send a FULLRESYNC reply in the specific case of a full resynchronization,
 * as a side effect setup the slave for a full sync in different ways:
 *
 * 1) Remember, into the slave client structure, the offset we sent
 *    here, so that if new slaves will later attach to the same
 *    background RDB saving process (by duplicating this client output
 *    buffer), we can get the right offset from this slave.
 * 2) Set the replication state of the slave to WAIT_BGSAVE_END so that
 *    we start accumulating differences from this point.
 * 3) Force the replication stream to re-emit a SELECT statement so
 *    the new slave incremental differences will start selecting the
 *    right database number.
 *
 * Normally this function should be called immediately after a successful
 * BGSAVE for replication was started, or when there is one already in
 * progress that we attached our slave to. */
int replicationSetupSlaveForFullResync(client *slave, long long offset) {
    char buf[128];
    int buflen;

    slave->psync_initial_offset = offset;
    slave->replstate = SLAVE_STATE_WAIT_BGSAVE_END;
    /* We are going to accumulate the incremental changes for this
     * slave as well. Set slaveseldb to -1 in order to force to re-emit
     * a SLEECT statement in the replication stream. */
    server.slaveseldb = -1;

    /* Don't send this reply to slaves that approached us with
     * the old SYNC command. */
    if (!(slave->flags & CLIENT_PRE_PSYNC)) {
        buflen = snprintf(buf,sizeof(buf),"+FULLRESYNC %s %lld\r\n",
                          server.runid,offset);
        if (write(slave->fd,buf,buflen) != buflen) {
            freeClientAsync(slave);
            return C_ERR;
        }
    }
    return C_OK;
}

//针对master，处理PSYNC命令，如果成功则返回C_OK，否则返回C_ERR

/* This function handles the PSYNC command from the point of view of a
 * master receiving a request for partial resynchronization.
 *
 * On success return C_OK, otherwise C_ERR is returned and we proceed
 * with the usual full resync. */
int masterTryPartialResynchronization(client *c) {
    long long psync_offset, psync_len;
    char *master_runid = c->argv[1]->ptr;
    char buf[128];
    int buflen;

    //当前master的runid是否和slave指定的runid相同，如果当前master的runid和slave指定的runid不相同，则没有必要继续了。

    /* Is the runid of this master the same advertised by the wannabe slave
     * via PSYNC? If runid changed this master is a different instance and
     * there is no way to continue. */
    if (strcasecmp(master_runid, server.runid)) {
        /* Run id "?" is used by slaves that want to force a full resync. */
        if (master_runid[0] != '?') {
            serverLog(LL_NOTICE,"Partial resynchronization not accepted: "
                "Runid mismatch (Client asked for runid '%s', my runid is '%s')",
                master_runid, server.runid);
        } else {
            serverLog(LL_NOTICE,"Full resync requested by slave %s",
                replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    //我们的缓存里面是否满足slave的同步需求？
    //如果不满足了，则需要全量同步

    /* We still have the data our slave is asking for? */
    if (getLongLongFromObjectOrReply(c,c->argv[2],&psync_offset,NULL) !=
       C_OK) goto need_full_resync;
    if (!server.repl_backlog ||
        psync_offset < server.repl_backlog_off ||
        psync_offset > (server.repl_backlog_off + server.repl_backlog_histlen))
    {
        serverLog(LL_NOTICE,
            "Unable to partial resync with slave %s for lack of backlog (Slave request was: %lld).", replicationGetSlaveName(c), psync_offset);
        if (psync_offset > server.master_repl_offset) {
            serverLog(LL_WARNING,
                "Warning: slave %s tried to PSYNC with an offset that is greater than the master replication offset.", replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    //如果到达这里，我们可以开始增量复制了:
    //1，设置slave的状态为SLAVE_STATE_ONLINE
    //2，回复client +CONTINUE
    //3，将backlog的数据发送给slaveof

    /* If we reached this point, we are able to perform a partial resync:
     * 1) Set client state to make it a slave.
     * 2) Inform the client we can continue with +CONTINUE
     * 3) Send the backlog data (from the offset to the end) to the slave. */
    c->flags |= CLIENT_SLAVE;
    c->replstate = SLAVE_STATE_ONLINE;
    c->repl_ack_time = server.unixtime;
    c->repl_put_online_on_ack = 0;
    listAddNodeTail(server.slaves,c);

    //由于这个时候reply缓存用于存放新增的数据，因此我们不能使用它，我们使用新的缓存。


    /* We can't use the connection buffers since they are used to accumulate
     * new commands at this stage. But we are sure the socket send buffer is
     * empty so this write will never fail actually. */
    buflen = snprintf(buf,sizeof(buf),"+CONTINUE\r\n");
    if (write(c->fd,buf,buflen) != buflen) {
        freeClientAsync(c);
        return C_OK;
    }
    psync_len = addReplyReplicationBacklog(c,psync_offset);
    serverLog(LL_NOTICE,
        "Partial resynchronization request from %s accepted. Sending %lld bytes of backlog starting from offset %lld.",
            replicationGetSlaveName(c),
            psync_len, psync_offset);
    /* Note that we don't need to set the selected DB at server.slaveseldb
     * to -1 to force the master to emit SELECT, since the slave already
     * has this state from the previous connection with the master. */

    refreshGoodSlavesCount();
    return C_OK; /* The caller can return, no full resync needed. */

need_full_resync:
    /* We need a full resync for some reason... Note that we can't
     * reply to PSYNC right now if a full SYNC is needed. The reply
     * must include the master offset at the time the RDB file we transfer
     * is generated, so we need to delay the reply to that moment. */
    return C_ERR;
}

//开启子进程备份RDB文件，具体是socket方式还是disk方式取决于配置文件的配置，且确认脚本被刷新了
//mincapa代表所有slave的容量

//处理处于WAIT_START状态的slave，使得这些slave准备犬粮同步RDB
//刷新Lua脚本

/* Start a BGSAVE for replication goals, which is, selecting the disk or
 * socket target depending on the configuration, and making sure that
 * the script cache is flushed before to start.
 *
 * The mincapa argument is the bitwise AND among all the slaves capabilities
 * of the slaves waiting for this BGSAVE, so represents the slave capabilities
 * all the slaves support. Can be tested via SLAVE_CAPA_* macros.
 *
 * Side effects, other than starting a BGSAVE:
 *
 * 1) Handle the slaves in WAIT_START state, by preparing them for a full
 *    sync if the BGSAVE was succesfully started, or sending them an error
 *    and dropping them from the list of slaves.
 *
 * 2) Flush the Lua scripting script cache if the BGSAVE was actually
 *    started.
 *
 * Returns C_OK on success or C_ERR otherwise. */
int startBgsaveForReplication(int mincapa) {
    int retval;
    int socket_target = server.repl_diskless_sync && (mincapa & SLAVE_CAPA_EOF);
    listIter li;
    listNode *ln;

    serverLog(LL_NOTICE,"Starting BGSAVE for SYNC with target: %s",
        socket_target ? "slaves sockets" : "disk");

    if (socket_target)
        retval = rdbSaveToSlavesSockets();
    else
        retval = rdbSaveBackground(server.rdb_filename);

    /* If we failed to BGSAVE, remove the slaves waiting for a full
     * resynchorinization from the list of salves, inform them with
     * an error about what happened, close the connection ASAP. */
    if (retval == C_ERR) {
        serverLog(LL_WARNING,"BGSAVE for replication failed");
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                slave->flags &= ~CLIENT_SLAVE;
                listDelNode(server.slaves,ln);
                addReplyError(slave,
                    "BGSAVE failed, replication can't continue");
                slave->flags |= CLIENT_CLOSE_AFTER_REPLY;
            }
        }
        return retval;
    }

    /* If the target is socket, rdbSaveToSlavesSockets() already setup
     * the salves for a full resync. Otherwise for disk target do it now.*/
    if (!socket_target) {
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                    replicationSetupSlaveForFullResync(slave,
                            getPsyncInitialOffset());
            }
        }
    }

    /* Flush the script cache, since we need that slave differences are
     * accumulated without requiring slaves to match our cached scripts. */
    if (retval == C_OK) replicationScriptCacheFlush();
    return retval;
}

//SYNC和PSYNC命令的主要实现

/* SYNC and PSYNC command implemenation. */
void syncCommand(client *c) {
    //如果客户端已经是SYNC模式，则直接返回

    /* ignore SYNC if already slave or in monitor mode */
    if (c->flags & CLIENT_SLAVE) return;

    //针对slave，但是和master的连接还没ok

    /* Refuse SYNC requests if we are a slave but the link with our master
     * is not ok... */
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED) {
        addReplyError(c,"Can't SYNC while not connected with my master");
        return;
    }

    //如果当前实例有未处理完的客户端请求，则不能进行复制
    //我们需要一个干净的buffer用于注册当前数据集和已经备份的数据集不一样的地方
    //从而可以复制给slave，这点需要注意

    /* SYNC can't be issued when the server has pending data to send to
     * the client about already issued commands. We need a fresh reply
     * buffer registering the differences between the BGSAVE and the current
     * dataset, so that we can copy to other slaves if needed. */
    if (clientHasPendingReplies(c)) {
        addReplyError(c,"SYNC and PSYNC are invalid with pending output");
        return;
    }

    serverLog(LL_NOTICE,"Slave %s asks for synchronization",
        replicationGetSlaveName(c));

    //如果是PSYNC命令，则尝试着进行增量复制
    //如果失败了，我们继续开始全量复制
    //而且masterTryPartialResynchronization会发送+FULLRESYNC <runid> <offset>给slave
    //因此slave会知道当前的runid和offset
    //对于slave来说，runid和PSYNC用来在连接断开的时候重新连接

    /* Try a partial resynchronization if this is a PSYNC command.
     * If it fails, we continue with usual full resynchronization, however
     * when this happens masterTryPartialResynchronization() already
     * replied with:
     *
     * +FULLRESYNC <runid> <offset>
     *
     * So the slave knows the new runid and offset to try a PSYNC later
     * if the connection with the master is lost. */
    if (!strcasecmp(c->argv[0]->ptr,"psync")) {
        if (masterTryPartialResynchronization(c) == C_OK) {
            server.stat_sync_partial_ok++;
            return; /* No full resync needed, return. */
        } else {
            char *master_runid = c->argv[1]->ptr;

            /* Increment stats for failed PSYNCs, but only if the
             * runid is not "?", as this is used by slaves to force a full
             * resync on purpose when they are not albe to partially
             * resync. */
            if (master_runid[0] != '?') server.stat_sync_partial_err++;
        }
    } else {
        /* If a slave uses SYNC, we are dealing with an old implementation
         * of the replication protocol (like redis-cli --slave). Flag the client
         * so that we don't expect to receive REPLCONF ACK feedbacks. */
        c->flags |= CLIENT_PRE_PSYNC;
    }

    /* Full resynchronization. */
    server.stat_sync_full++;

    //slave等待master开始复制的过程

    /* Setup the slave as one waiting for BGSAVE to start. The following code
     * paths will change the state if we handle the slave differently. */
    c->replstate = SLAVE_STATE_WAIT_BGSAVE_START;
    if (server.repl_disable_tcp_nodelay)
        anetDisableTcpNoDelay(NULL, c->fd); /* Non critical if it fails. */
    c->repldbfd = -1;
    c->flags |= CLIENT_SLAVE;
    listAddNodeTail(server.slaves,c);

    //如果子进程正在备份，且是RDB disk方式
    /* CASE 1: BGSAVE is in progress, with disk target. */
    if (server.rdb_child_pid != -1 &&
        server.rdb_child_type == RDB_CHILD_TYPE_DISK)
    {
        //这是子进程正在进行RDB文件备份，又来了slave的情况
        //子进程正在进行RDB文件备份，我们来检查一下如果有其他的slave正在处于SLAVE_STATE_WAIT_BGSAVE_END状态

        /* Ok a background save is in progress. Let's check if it is a good
         * one for replication, i.e. if there is another slave that is
         * registering differences since the server forked to save. */
        client *slave;
        listNode *ln;
        listIter li;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) break;
        }
        //接受这个slave
        /* To attach this slave, we check that it has at least all the
         * capabilities of the slave that triggered the current BGSAVE. */
        if (ln && ((c->slave_capa & slave->slave_capa) == slave->slave_capa)) {
            //将之前正在等待的slave的buffer copy给新增的slave的client buffer区域，因此
            //这个新来的slave可以在RDB文件备份好之后一起进行复制。

            /* Perfect, the server is already registering differences for
             * another slave. Set the right state, and copy the buffer. */
            copyClientOutputBuffer(c,slave);
            replicationSetupSlaveForFullResync(c,slave->psync_initial_offset);
            serverLog(LL_NOTICE,"Waiting for end of BGSAVE for SYNC");
        } else {
            //否则需要下一次备份RDB之后再进行复制咯
            /* No way, we need to wait for the next BGSAVE in order to
             * register differences. */
            serverLog(LL_NOTICE,"Waiting for next BGSAVE for SYNC");
        }

    //如果有子进程正在备份，且是diskless方式
    /* CASE 2: BGSAVE is in progress, with socket target. */
    } else if (server.rdb_child_pid != -1 &&
               server.rdb_child_type == RDB_CHILD_TYPE_SOCKET)
    {
        //diskless方式的复制已经正在进行咯，需要等待下次哦

        /* There is an RDB child process but it is writing directly to
         * children sockets. We need to wait for the next BGSAVE
         * in order to synchronize. */
        serverLog(LL_NOTICE,"Waiting for next BGSAVE for SYNC");

    //如果没有子进程正在复制
    /* CASE 3: There is no BGSAVE is progress. */
    } else {
        //diskless复制方式异步之行，在replicationCron中实现，也是为了延迟一段时间才开始，为了等待更多的slave
        //的复制请求过来
        if (server.repl_diskless_sync && (c->slave_capa & SLAVE_CAPA_EOF)) {
            /* Diskless replication RDB child is created inside
             * replicationCron() since we want to delay its start a
             * few seconds to wait for more slaves to arrive. */
            if (server.repl_diskless_sync_delay)
                serverLog(LL_NOTICE,"Delay next BGSAVE for SYNC");
        } else {
            //启动子进程进行复制
            /* Target is disk (or the slave is not capable of supporting
             * diskless replication) and we don't have a BGSAVE in progress,
             * let's start one. */
            if (startBgsaveForReplication(c->slave_capa) != C_OK) return;
        }
    }

    if (listLength(server.slaves) == 1 && server.repl_backlog == NULL)
        createReplicationBacklog();
    return;
}

/* REPLCONF <option> <value> <option> <value> ...
 * This command is used by a slave in order to configure the replication
 * process before starting it with the SYNC command.
 *
 * Currently the only use of this command is to communicate to the master
 * what is the listening port of the Slave redis instance, so that the
 * master can accurately list slaves and their listening ports in
 * the INFO output.
 *
 * In the future the same command can be used in order to configure
 * the replication to initiate an incremental replication instead of a
 * full resync. */
void replconfCommand(client *c) {
    int j;

    if ((c->argc % 2) == 0) {
        /* Number of arguments must be odd to make sure that every
         * option has a corresponding value. */
        addReply(c,shared.syntaxerr);
        return;
    }

    /* Process every option-value pair. */
    for (j = 1; j < c->argc; j+=2) {
        if (!strcasecmp(c->argv[j]->ptr,"listening-port")) {
            long port;

            if ((getLongFromObjectOrReply(c,c->argv[j+1],
                    &port,NULL) != C_OK))
                return;
            c->slave_listening_port = port;
        } else if (!strcasecmp(c->argv[j]->ptr,"capa")) {
            /* Ignore capabilities not understood by this master. */
            if (!strcasecmp(c->argv[j+1]->ptr,"eof"))
                c->slave_capa |= SLAVE_CAPA_EOF;
        } else if (!strcasecmp(c->argv[j]->ptr,"ack")) {
            /* REPLCONF ACK is used by slave to inform the master the amount
             * of replication stream that it processed so far. It is an
             * internal only command that normal clients should never use. */
            long long offset;

            if (!(c->flags & CLIENT_SLAVE)) return;
            if ((getLongLongFromObject(c->argv[j+1], &offset) != C_OK))
                return;
            if (offset > c->repl_ack_off)
                c->repl_ack_off = offset;
            c->repl_ack_time = server.unixtime;
            /* If this was a diskless replication, we need to really put
             * the slave online when the first ACK is received (which
             * confirms slave is online and ready to get more data). */
            if (c->repl_put_online_on_ack && c->replstate == SLAVE_STATE_ONLINE)
                putSlaveOnline(c);
            /* Note: this command does not reply anything! */
            return;
        } else if (!strcasecmp(c->argv[j]->ptr,"getack")) {
            /* REPLCONF GETACK is used in order to request an ACK ASAP
             * to the slave. */
            if (server.masterhost && server.master) replicationSendAck();
            /* Note: this command does not reply anything! */
        } else {
            addReplyErrorFormat(c,"Unrecognized REPLCONF option: %s",
                (char*)c->argv[j]->ptr);
            return;
        }
    }
    addReply(c,shared.ok);
}

//这个方法用于发送完RDB文件之后，让slave上线，需要注意的是在这里，我们将备份RDB的过程中增量的命令发送给slave
//主要做的事情如下：
//1，修改slave的状态为ONLINE
//2，确认写事件重新被注册
//3，更新好的slave的数量

/* This function puts a slave in the online state, and should be called just
 * after a slave received the RDB file for the initial synchronization, and
 * we are finally ready to send the incremental stream of commands.
 *
 * It does a few things:
 *
 * 1) Put the slave in ONLINE state (useless when the function is called
 *    because state is already ONLINE but repl_put_online_on_ack is true).
 * 2) Make sure the writable event is re-installed, since calling the SYNC
 *    command disables it, so that we can accumulate output buffer without
 *    sending it to the slave.
 * 3) Update the count of good slaves. */
void putSlaveOnline(client *slave) {
    slave->replstate = SLAVE_STATE_ONLINE;
    slave->repl_put_online_on_ack = 0;
    slave->repl_ack_time = server.unixtime; /* Prevent false timeout. */
    if (aeCreateFileEvent(server.el, slave->fd, AE_WRITABLE,
        sendReplyToClient, slave) == AE_ERR) {
        serverLog(LL_WARNING,"Unable to register writable event for slave bulk transfer: %s", strerror(errno));
        freeClient(slave);
        return;
    }
    refreshGoodSlavesCount();
    serverLog(LL_NOTICE,"Synchronization with slave %s succeeded",
        replicationGetSlaveName(slave));
}

//用于将RDB文件发送给slave

void sendBulkToSlave(aeEventLoop *el, int fd, void *privdata, int mask) {
    client *slave = privdata;
    UNUSED(el);
    UNUSED(mask);
    char buf[PROTO_IOBUF_LEN];
    ssize_t nwritten, buflen;

    //在发送RDB文件之前，我们发送一个复制配置的前言，目前前言仅仅是RDB文件的大小

    /* Before sending the RDB file, we send the preamble as configured by the
     * replication process. Currently the preamble is just the bulk count of
     * the file in the form "$<length>\r\n". */
    if (slave->replpreamble) {
        nwritten = write(fd,slave->replpreamble,sdslen(slave->replpreamble));
        if (nwritten == -1) {
            serverLog(LL_VERBOSE,"Write error sending RDB preamble to slave: %s",
                strerror(errno));
            freeClient(slave);
            return;
        }
        server.stat_net_output_bytes += nwritten;
        sdsrange(slave->replpreamble,nwritten,-1);
        if (sdslen(slave->replpreamble) == 0) {
            sdsfree(slave->replpreamble);
            slave->replpreamble = NULL;
            /* fall through sending data. */
        } else {
            return;
        }
    }

    //如果前言发送完毕，开始发送RDB文件

    /* If the preamble was already transfered, send the RDB bulk data. */
    lseek(slave->repldbfd,slave->repldboff,SEEK_SET);
    buflen = read(slave->repldbfd,buf,PROTO_IOBUF_LEN);
    if (buflen <= 0) {
        serverLog(LL_WARNING,"Read error sending DB to slave: %s",
            (buflen == 0) ? "premature EOF" : strerror(errno));
        freeClient(slave);
        return;
    }
    if ((nwritten = write(fd,buf,buflen)) == -1) {
        if (errno != EAGAIN) {
            serverLog(LL_WARNING,"Write error sending DB to slave: %s",
                strerror(errno));
            freeClient(slave);
        }
        return;
    }
    slave->repldboff += nwritten;
    server.stat_net_output_bytes += nwritten;
    //如果发送完毕，则取消写事件处理器
    if (slave->repldboff == slave->repldbsize) {
        close(slave->repldbfd);
        slave->repldbfd = -1;
        aeDeleteFileEvent(server.el,slave->fd,AE_WRITABLE);
        putSlaveOnline(slave);
    }
}

//这个方法在备份RDB文件之后被调用

/* This function is called at the end of every background saving,
 * or when the replication RDB transfer strategy is modified from
 * disk to socket or the other way around.
 *
 * The goal of this function is to handle slaves waiting for a successful
 * background saving in order to perform non-blocking synchronization, and
 * to schedule a new BGSAVE if there are slaves that attached while a
 * BGSAVE was in progress, but it was not a good one for replication (no
 * other slave was accumulating differences).
 *
 * The argument bgsaveerr is C_OK if the background saving succeeded
 * otherwise C_ERR is passed to the function.
 * The 'type' argument is the type of the child that terminated
 * (if it had a disk or socket target). */
void updateSlavesWaitingBgsave(int bgsaveerr, int type) {
    listNode *ln;
    int startbgsave = 0;
    int mincapa = -1;
    listIter li;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
            startbgsave = 1;
            mincapa = (mincapa == -1) ? slave->slave_capa :
                                        (mincapa & slave->slave_capa);
        } else if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) {
            struct redis_stat buf;

            /* If this was an RDB on disk save, we have to prepare to send
             * the RDB from disk to the slave socket. Otherwise if this was
             * already an RDB -> Slaves socket transfer, used in the case of
             * diskless replication, our work is trivial, we can just put
             * the slave online. */
            if (type == RDB_CHILD_TYPE_SOCKET) {
                serverLog(LL_NOTICE,
                    "Streamed RDB transfer with slave %s succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming",
                        replicationGetSlaveName(slave));
                /* Note: we wait for a REPLCONF ACK message from slave in
                 * order to really put it online (install the write handler
                 * so that the accumulated data can be transfered). However
                 * we change the replication state ASAP, since our slave
                 * is technically online now. */
                slave->replstate = SLAVE_STATE_ONLINE;
                slave->repl_put_online_on_ack = 1;
                slave->repl_ack_time = server.unixtime; /* Timeout otherwise. */
            } else {
                if (bgsaveerr != C_OK) {
                    freeClient(slave);
                    serverLog(LL_WARNING,"SYNC failed. BGSAVE child returned an error");
                    continue;
                }
                if ((slave->repldbfd = open(server.rdb_filename,O_RDONLY)) == -1 ||
                    redis_fstat(slave->repldbfd,&buf) == -1) {
                    freeClient(slave);
                    serverLog(LL_WARNING,"SYNC failed. Can't open/stat DB after BGSAVE: %s", strerror(errno));
                    continue;
                }
                slave->repldboff = 0;
                slave->repldbsize = buf.st_size;
                slave->replstate = SLAVE_STATE_SEND_BULK;
                slave->replpreamble = sdscatprintf(sdsempty(),"$%lld\r\n",
                    (unsigned long long) slave->repldbsize);

                aeDeleteFileEvent(server.el,slave->fd,AE_WRITABLE);
                if (aeCreateFileEvent(server.el, slave->fd, AE_WRITABLE, sendBulkToSlave, slave) == AE_ERR) {
                    freeClient(slave);
                    continue;
                }
            }
        }
    }
    if (startbgsave) startBgsaveForReplication(mincapa);
}

/* ----------------------------------- SLAVE -------------------------------- */

//握手阶段的状态从REPL_STATE_RECEIVE_PONG到REPL_STATE_RECEIVE_PSYNC

/* Returns 1 if the given replication state is a handshake state,
 * 0 otherwise. */
int slaveIsInHandshakeState(void) {
    return server.repl_state >= REPL_STATE_RECEIVE_PONG &&
           server.repl_state <= REPL_STATE_RECEIVE_PSYNC;
}

/* Avoid the master to detect the slave is timing out while loading the
 * RDB file in initial synchronization. We send a single newline character
 * that is valid protocol but is guaranteed to either be sent entierly or
 * not, since the byte is indivisible.
 *
 * The function is called in two contexts: while we flush the current
 * data with emptyDb(), and while we load the new data received as an
 * RDB file from the master. */
void replicationSendNewlineToMaster(void) {
    static time_t newline_sent;
    if (time(NULL) != newline_sent) {
        newline_sent = time(NULL);
        if (write(server.repl_transfer_s,"\n",1) == -1) {
            /* Pinging back in this stage is best-effort. */
        }
    }
}

/* Callback used by emptyDb() while flushing away old data to load
 * the new dataset received by the master. */
void replicationEmptyDbCallback(void *privdata) {
    UNUSED(privdata);
    replicationSendNewlineToMaster();
}

//一旦我们和master建立了连接，同步进行过了，这个方法才讲master信息存储到server.master中

/* Once we have a link with the master and the synchroniziation was
 * performed, this function materializes the master client we store
 * at server.master, starting from the specified file descriptor. */
void replicationCreateMasterClient(int fd) {
    server.master = createClient(fd);
    server.master->flags |= CLIENT_MASTER;
    server.master->authenticated = 1;
    server.repl_state = REPL_STATE_CONNECTED;
    server.master->reploff = server.repl_master_initial_offset;
    memcpy(server.master->replrunid, server.repl_master_runid,
        sizeof(server.repl_master_runid));
    //如果master的复制offser为-1，则说明这个mater是老版本的master，不支持PSYNC

    /* If master offset is set to -1, this master is old and is not
     * PSYNC capable, so we flag it accordingly. */
    if (server.master->reploff == -1)
        server.master->flags |= CLIENT_PRE_PSYNC;
}

//异步的读取master发送过来的RDB文件

/* Asynchronously read the SYNC payload we receive from a master */
#define REPL_MAX_WRITTEN_BEFORE_FSYNC (1024*1024*8) /* 8 MB */
void readSyncBulkPayload(aeEventLoop *el, int fd, void *privdata, int mask) {
    char buf[4096];
    ssize_t nread, readlen;
    off_t left;
    UNUSED(el);
    UNUSED(privdata);
    UNUSED(mask);

    //master的写文件以EOF结束

    /* Static vars used to hold the EOF mark, and the last bytes received
     * form the server: when they match, we reached the end of the transfer. */
    static char eofmark[CONFIG_RUN_ID_SIZE];
    static char lastbytes[CONFIG_RUN_ID_SIZE];
    static int usemark = 0;

    //如果repl_transfer_size＝＝－1，我们需要从master读取内容

    /* If repl_transfer_size == -1 we still have to read the bulk length
     * from the master reply. */
    if (server.repl_transfer_size == -1) {
        if (syncReadLine(fd,buf,1024,server.repl_syncio_timeout*1000) == -1) {
            serverLog(LL_WARNING,
                "I/O error reading bulk count from MASTER: %s",
                strerror(errno));
            goto error;
        }
        //master取消了复制
        if (buf[0] == '-') {
            serverLog(LL_WARNING,
                "MASTER aborted replication with an error: %s",
                buf+1);
            goto error;
        } else if (buf[0] == '\0') {
            //这个时候读到'\0'代表PING,因此更新上次交互的时间。
            /* At this stage just a newline works as a PING in order to take
             * the connection live. So we refresh our last interaction
             * timestamp. */
            server.repl_transfer_lastio = server.unixtime;
            return;
        } else if (buf[0] != '$') {
            serverLog(LL_WARNING,"Bad protocol from MASTER, the first byte is not '$' (we received '%s'), are you sure the host and port are right?", buf);
            goto error;
        }

        //这里对于RDB文件传输有两种可能的方式：
        //1，一种是使用$<count>格式
        //2，一种是diskless方式传输，这种方式master并不知道RDB文件的大小，因此使用下面的格式

        //$EOF:<40 bytes delimiter>

        //eofmark数组用于存放40字节的delimiter，每次读将最后读到的40字节内容放在lastbytes数组中
        //通过比较lastbytes和eofmark的值来确定diskless方式是否到了最后，跟RDB disk方式不同，EDB disk方式
        //在最开始就告诉了客户端要读多少字节

        /* There are two possible forms for the bulk payload. One is the
         * usual $<count> bulk format. The other is used for diskless transfers
         * when the master does not know beforehand the size of the file to
         * transfer. In the latter case, the following format is used:
         *
         * $EOF:<40 bytes delimiter>
         *
         * At the end of the file the announced delimiter is transmitted. The
         * delimiter is long and random enough that the probability of a
         * collision with the actual file content can be ignored. */

         //diskless方式
        if (strncmp(buf+1,"EOF:",4) == 0 && strlen(buf+5) >= CONFIG_RUN_ID_SIZE) {
            usemark = 1;
            memcpy(eofmark,buf+5,CONFIG_RUN_ID_SIZE);
            memset(lastbytes,0,CONFIG_RUN_ID_SIZE);
            /* Set any repl_transfer_size to avoid entering this code path
             * at the next call. */
            server.repl_transfer_size = 0;
            serverLog(LL_NOTICE,
                "MASTER <-> SLAVE sync: receiving streamed RDB from master");
        } else {
            //RDB文件方式
            usemark = 0;
            server.repl_transfer_size = strtol(buf+1,NULL,10);
            serverLog(LL_NOTICE,
                "MASTER <-> SLAVE sync: receiving %lld bytes from master",
                (long long) server.repl_transfer_size);
        }
        return;
    }

    /* Read bulk data */
    if (usemark) {//Diskless方式
        readlen = sizeof(buf);
    } else {
        left = server.repl_transfer_size - server.repl_transfer_read;
        readlen = (left < (signed)sizeof(buf)) ? left : (signed)sizeof(buf);
    }

    nread = read(fd,buf,readlen);
    if (nread <= 0) {
        serverLog(LL_WARNING,"I/O error trying to sync with MASTER: %s",
            (nread == -1) ? strerror(errno) : "connection lost");
        cancelReplicationHandshake();
        return;
    }
    server.stat_net_input_bytes += nread;

    /* When a mark is used, we want to detect EOF asap in order to avoid
     * writing the EOF mark into the file... */
    int eof_reached = 0;

    if (usemark) {//Diskless方式
        /* Update the last bytes array, and check if it matches our delimiter.*/
        if (nread >= CONFIG_RUN_ID_SIZE) {
            memcpy(lastbytes,buf+nread-CONFIG_RUN_ID_SIZE,CONFIG_RUN_ID_SIZE);
        } else {
            int rem = CONFIG_RUN_ID_SIZE-nread;
            memmove(lastbytes,lastbytes+nread,rem);
            memcpy(lastbytes+rem,buf,nread);
        }
        if (memcmp(lastbytes,eofmark,CONFIG_RUN_ID_SIZE) == 0) eof_reached = 1;
    }

    server.repl_transfer_lastio = server.unixtime;
    if (write(server.repl_transfer_fd,buf,nread) != nread) {
        serverLog(LL_WARNING,"Write error or short write writing to the DB dump file needed for MASTER <-> SLAVE synchronization: %s", strerror(errno));
        goto error;
    }
    server.repl_transfer_read += nread;

    //如果到了RDB文件末尾、删除最后的40字节
    //Diskless方式，最后四十字节也是delimiter

    /* Delete the last 40 bytes from the file if we reached EOF. */
    if (usemark && eof_reached) {
        if (ftruncate(server.repl_transfer_fd,
            server.repl_transfer_read - CONFIG_RUN_ID_SIZE) == -1)
        {
            serverLog(LL_WARNING,"Error truncating the RDB file received from the master for SYNC: %s", strerror(errno));
            goto error;
        }
    }

    //将数据同步到磁盘

    /* Sync data on disk from time to time, otherwise at the end of the transfer
     * we may suffer a big delay as the memory buffers are copied into the
     * actual disk. */
    if (server.repl_transfer_read >=
        server.repl_transfer_last_fsync_off + REPL_MAX_WRITTEN_BEFORE_FSYNC)
    {
        off_t sync_size = server.repl_transfer_read -
                          server.repl_transfer_last_fsync_off;
        rdb_fsync_range(server.repl_transfer_fd,
            server.repl_transfer_last_fsync_off, sync_size);
        server.repl_transfer_last_fsync_off += sync_size;
    }

    /* Check if the transfer is now complete */
    if (!usemark) {
        if (server.repl_transfer_read == server.repl_transfer_size)
            eof_reached = 1;
    }

    if (eof_reached) {
        //重命名RDB文件
        if (rename(server.repl_transfer_tmpfile,server.rdb_filename) == -1) {
            serverLog(LL_WARNING,"Failed trying to rename the temp DB into dump.rdb in MASTER <-> SLAVE synchronization: %s", strerror(errno));
            cancelReplicationHandshake();
            return;
        }
        serverLog(LL_NOTICE, "MASTER <-> SLAVE sync: Flushing old data");
        signalFlushedDb(-1);
        emptyDb(
            -1,
            server.repl_slave_lazy_flush ? EMPTYDB_ASYNC : EMPTYDB_NO_FLAGS,
            replicationEmptyDbCallback);
        //在将EDB文件导入内存之前，我们需要删除读处理器，防止再读

        /* Before loading the DB into memory we need to delete the readable
         * handler, otherwise it will get called recursively since
         * rdbLoad() will call the event loop to process events from time to
         * time for non blocking loading. */
        aeDeleteFileEvent(server.el,server.repl_transfer_s,AE_READABLE);
        serverLog(LL_NOTICE, "MASTER <-> SLAVE sync: Loading DB in memory");
        if (rdbLoad(server.rdb_filename) != C_OK) {
            serverLog(LL_WARNING,"Failed trying to load the MASTER synchronization DB from disk");
            cancelReplicationHandshake();
            return;
        }
        //最后保存master

        /* Final setup of the connected slave <- master link */
        zfree(server.repl_transfer_tmpfile);
        close(server.repl_transfer_fd);
        replicationCreateMasterClient(server.repl_transfer_s);
        serverLog(LL_NOTICE, "MASTER <-> SLAVE sync: Finished with success");
        //重启AOF系统，将会触发AOF重写

        /* Restart the AOF subsystem now that we finished the sync. This
         * will trigger an AOF rewrite, and when done will start appending
         * to the new file. */
        if (server.aof_state != AOF_OFF) {
            int retry = 10;

            stopAppendOnly();
            while (retry-- && startAppendOnly() == C_ERR) {
                serverLog(LL_WARNING,"Failed enabling the AOF after successful master synchronization! Trying it again in one second.");
                sleep(1);
            }
            if (!retry) {
                serverLog(LL_WARNING,"FATAL: this slave instance finished the synchronization with its master, but the AOF can't be turned on. Exiting now.");
                exit(1);
            }
        }
    }

    return;

error:
    cancelReplicationHandshake();
    return;
}

//salve向master同步发送命令，通常用于SYNC同步之前发送AUTH和REPLCONF。
//这个接口返回sds字符串，代表方法的操作结果。

//读写分别有超时时间，读取成功刷新repl_transfer_lastio

/* Send a synchronous command to the master. Used to send AUTH and
 * REPLCONF commands before starting the replication with SYNC.
 *
 * The command returns an sds string representing the result of the
 * operation. On error the first byte is a "-".
 */
#define SYNC_CMD_READ (1<<0)
#define SYNC_CMD_WRITE (1<<1)
#define SYNC_CMD_FULL (SYNC_CMD_READ|SYNC_CMD_WRITE)
char *sendSynchronousCommand(int flags, int fd, ...) {

    //创建一个命令然后发送给master，我们使用简单的内联协议，这里只是简单的发送字符串。

    /* Create the command to send to the master, we use simple inline
     * protocol for simplicity as currently we only send simple strings. */
    if (flags & SYNC_CMD_WRITE) {
        char *arg;
        va_list ap;
        sds cmd = sdsempty();
        va_start(ap,fd);

        while(1) {
            arg = va_arg(ap, char*);
            if (arg == NULL) break;

            if (sdslen(cmd) != 0) cmd = sdscatlen(cmd," ",1);
            cmd = sdscat(cmd,arg);
        }
        cmd = sdscatlen(cmd,"\r\n",2);

        /* Transfer command to the server. */
        if (syncWrite(fd,cmd,sdslen(cmd),server.repl_syncio_timeout*1000)
            == -1)
        {
            sdsfree(cmd);
            return sdscatprintf(sdsempty(),"-Writing to master: %s",
                    strerror(errno));
        }
        sdsfree(cmd);
        va_end(ap);
    }

    /* Read the reply from the server. */
    if (flags & SYNC_CMD_READ) {
        char buf[256];

        if (syncReadLine(fd,buf,sizeof(buf),server.repl_syncio_timeout*1000)
            == -1)
        {
            return sdscatprintf(sdsempty(),"-Reading from master: %s",
                    strerror(errno));
        }
        server.repl_transfer_lastio = server.unixtime;
        return sdsnew(buf);
    }
    return NULL;
}

//如果是slave重新连接master，这里执行增量同步

//1，这个方法被设计用于syncWithMaster,传入一个已经建立连接的fd
//2，这个方法不会关闭fd，然而，如果成功复制，这个文件描述符会被存入server.master

//对于read_reply参数
//如果是0:
//该方法会把PSYNC写入socket，而且需要重新调用
//如果是1:
//是为了读取命令的回复

//这是为了实现非阻塞操作，我们写入数据、回到event loop、然后回来读数据
//------    完美异步   -------

//当read_reply为0的时候
//返回PSYNC_WRITE_ERR表明写错误
//返回PSYNC_WAIT_REPLY说明我们需要重新调用一次，且让参数为1，来读取回复
//然而即使参数为1也不一定一次能够成功，我们可能需要再调用一次来读取足够的数据，这个时候返回PSYNC_WAIT_REPLY

//返回PSYNC_CONTINUE    : PSYNC命令成功，我们可以继续
//PSYNC_FULLRESYNC     :    PSYNC是被支持的，但是我们需要全量同步，这个时候run id和全局的offset会被记住
//PSYNC_NOT_SUPPORTED   :   服务器不支持PSYNC,fall back to sync


/* Try a partial resynchronization with the master if we are about to reconnect.
 * If there is no cached master structure, at least try to issue a
 * "PSYNC ? -1" command in order to trigger a full resync using the PSYNC
 * command in order to obtain the master run id and the master replication
 * global offset.
 *
 * This function is designed to be called from syncWithMaster(), so the
 * following assumptions are made:
 *
 * 1) We pass the function an already connected socket "fd".
 * 2) This function does not close the file descriptor "fd". However in case
 *    of successful partial resynchronization, the function will reuse
 *    'fd' as file descriptor of the server.master client structure.
 *
 * The function is split in two halves: if read_reply is 0, the function
 * writes the PSYNC command on the socket, and a new function call is
 * needed, with read_reply set to 1, in order to read the reply of the
 * command. This is useful in order to support non blocking operations, so
 * that we write, return into the event loop, and read when there are data.
 *
 * When read_reply is 0 the function returns PSYNC_WRITE_ERR if there
 * was a write error, or PSYNC_WAIT_REPLY to signal we need another call
 * with read_reply set to 1. However even when read_reply is set to 1
 * the function may return PSYNC_WAIT_REPLY again to signal there were
 * insufficient data to read to complete its work. We should re-enter
 * into the event loop and wait in such a case.
 *
 * The function returns:
 *
 * PSYNC_CONTINUE: If the PSYNC command succeded and we can continue.
 * PSYNC_FULLRESYNC: If PSYNC is supported but a full resync is needed.
 *                   In this case the master run_id and global replication
 *                   offset is saved.
 * PSYNC_NOT_SUPPORTED: If the server does not understand PSYNC at all and
 *                      the caller should fall back to SYNC.
 * PSYNC_WRITE_ERR: There was an error writing the command to the socket.
 * PSYNC_WAIT_REPLY: Call again the function with read_reply set to 1.
 *
 * Notable side effects:
 *
 * 1) As a side effect of the function call the function removes the readable
 *    event handler from "fd", unless the return value is PSYNC_WAIT_REPLY.
 * 2) server.repl_master_initial_offset is set to the right value according
 *    to the master reply. This will be used to populate the 'server.master'
 *    structure replication offset.
 */

#define PSYNC_WRITE_ERROR 0
#define PSYNC_WAIT_REPLY 1
#define PSYNC_CONTINUE 2
#define PSYNC_FULLRESYNC 3
#define PSYNC_NOT_SUPPORTED 4
int slaveTryPartialResynchronization(int fd, int read_reply) {
    char *psync_runid;
    char psync_offset[32];
    sds reply;

    //read_reply=0

    /* Writing half */
    if (!read_reply) {
        /* Initially set repl_master_initial_offset to -1 to mark the current
         * master run_id and offset as not valid. Later if we'll be able to do
         * a FULL resync using the PSYNC command we'll set the offset at the
         * right value, so that this information will be propagated to the
         * client structure representing the master into server.master. */
        server.repl_master_initial_offset = -1;

        if (server.cached_master) {
            psync_runid = server.cached_master->replrunid;
            snprintf(psync_offset,sizeof(psync_offset),"%lld", server.cached_master->reploff+1);
            serverLog(LL_NOTICE,"Trying a partial resynchronization (request %s:%s).", psync_runid, psync_offset);
        } else {
            serverLog(LL_NOTICE,"Partial resynchronization not possible (no cached master)");
            psync_runid = "?";
            memcpy(psync_offset,"-1",3);
        }

        /* Issue the PSYNC command */
        reply = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"PSYNC",psync_runid,psync_offset,NULL);
        if (reply != NULL) {
            serverLog(LL_WARNING,"Unable to send PSYNC to master: %s",reply);
            sdsfree(reply);
            aeDeleteFileEvent(server.el,fd,AE_READABLE);
            return PSYNC_WRITE_ERROR;
        }
        return PSYNC_WAIT_REPLY;
    }

    /* Reading half */
    reply = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
    if (sdslen(reply) == 0) {
        /* The master may send empty newlines after it receives PSYNC
         * and before to reply, just to keep the connection alive. */
        sdsfree(reply);
        return PSYNC_WAIT_REPLY;
    }

    //如果都到回复，则删除读事件
    aeDeleteFileEvent(server.el,fd,AE_READABLE);

    //如果需要全量同步

    if (!strncmp(reply,"+FULLRESYNC",11)) {
        char *runid = NULL, *offset = NULL;

        //返回run id 和 offset
        /* FULL RESYNC, parse the reply in order to extract the run id
         * and the replication offset. */
        runid = strchr(reply,' ');
        if (runid) {
            runid++;
            offset = strchr(runid,' ');
            if (offset) offset++;
        }
        if (!runid || !offset || (offset-runid-1) != CONFIG_RUN_ID_SIZE) {
            serverLog(LL_WARNING,
                "Master replied with wrong +FULLRESYNC syntax.");
            /* This is an unexpected condition, actually the +FULLRESYNC
             * reply means that the master supports PSYNC, but the reply
             * format seems wrong. To stay safe we blank the master
             * runid to make sure next PSYNCs will fail. */
            memset(server.repl_master_runid,0,CONFIG_RUN_ID_SIZE+1);
        } else {
            //记住run和offset
            memcpy(server.repl_master_runid, runid, offset-runid-1);
            server.repl_master_runid[CONFIG_RUN_ID_SIZE] = '\0';
            server.repl_master_initial_offset = strtoll(offset,NULL,10);
            serverLog(LL_NOTICE,"Full resync from master: %s:%lld",
                server.repl_master_runid,
                server.repl_master_initial_offset);
        }
        //因为需要全量同步了，所以可以删除缓存的master了，等全量同步完了之后，会重新保存master
        /* We are going to full resync, discard the cached master structure. */
        replicationDiscardCachedMaster();
        sdsfree(reply);
        return PSYNC_FULLRESYNC;
    }

    //如果可以增量同步
    if (!strncmp(reply,"+CONTINUE",9)) {
        /* Partial resync was accepted, set the replication state accordingly */
        serverLog(LL_NOTICE,
            "Successful partial resynchronization with master.");
        sdsfree(reply);
        replicationResurrectCachedMaster(fd);
        return PSYNC_CONTINUE;
    }

    /* If we reach this point we received either an error since the master does
     * not understand PSYNC, or an unexpected reply from the master.
     * Return PSYNC_NOT_SUPPORTED to the caller in both cases. */

    if (strncmp(reply,"-ERR",4)) {
        /* If it's not an error, log the unexpected event. */
        serverLog(LL_WARNING,
            "Unexpected reply to PSYNC from master: %s", reply);
    } else {
        serverLog(LL_NOTICE,
            "Master does not support PSYNC or is in "
            "error state (reply: %s)", reply);
    }
    sdsfree(reply);
    replicationDiscardCachedMaster();
    return PSYNC_NOT_SUPPORTED;
}

//针对slave
//当接收到master的I/O事件，被调用

void syncWithMaster(aeEventLoop *el, int fd, void *privdata, int mask) {
    char tmpfile[256], *err = NULL;
    int dfd, maxtries = 5;
    int sockerr = 0, psync_result;
    socklen_t errlen = sizeof(sockerr);
    UNUSED(el);
    UNUSED(privdata);
    UNUSED(mask);

    //如果当前实例刚好通过slaveof no one命令转换为master，则直接返回，这种情况什么时候会发生呢？
    //如果刚slaveof完又slaveof no one

    /* If this event fired after the user turned the instance into a master
     * with SLAVEOF NO ONE we must just return ASAP. */
    if (server.repl_state == REPL_STATE_NONE) {
        close(fd);
        return;
    }

    /* Check for errors in the socket. */
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) == -1)
        sockerr = errno;
    if (sockerr) {
        serverLog(LL_WARNING,"Error condition on socket for SYNC: %s",
            strerror(sockerr));
        goto error;
    }

    //如果slave的复制状态为REPL_STATE_CONNECTING,这应该是正确的状态

    //1，之前注册了读写事件，现在移除写事件
    //2，复制状态变化：REPL_STATE_CONNECTING  ->  REPL_STATE_RECEIVE_PONG
    //3，然后再PING一下master，同步等待master回复

    /* Send a PING to check the master is able to reply without errors. */
    if (server.repl_state == REPL_STATE_CONNECTING) {
        serverLog(LL_NOTICE,"Non blocking connect for SYNC fired the event.");
        /* Delete the writable event so that the readable event remains
         * registered and we can wait for the PONG reply. */
        aeDeleteFileEvent(server.el,fd,AE_WRITABLE);
        server.repl_state = REPL_STATE_RECEIVE_PONG;
        /* Send the PING, don't check for errors at all, we have the timeout
         * that will take care about this. */
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"PING",NULL);
        if (err) goto write_error;
        return;
    }

    //如果slave的复制状态为REPL_STATE_RECEIVE_PONG，则从master同步读取信息

    /* Receive the PONG command. */
    if (server.repl_state == REPL_STATE_RECEIVE_PONG) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);

        //上面我们已经发送了一个PING了，这边只接受两个正确的回复，＋PONG或者是认证失败信息
        //对于＋PONG信息之验证＋号

        //状态转变：REPL_STATE_RECEIVE_PONG  －>  REPL_STATE_SEND_AUTH

        /* We accept only two replies as valid, a positive +PONG reply
         * (we just check for "+") or an authentication error.
         * Note that older versions of Redis replied with "operation not
         * permitted" instead of using a proper error code, so we test
         * both. */
        if (err[0] != '+' &&
            strncmp(err,"-NOAUTH",7) != 0 &&
            strncmp(err,"-ERR operation not permitted",28) != 0)
        {
            serverLog(LL_WARNING,"Error reply to PING from master: '%s'",err);
            sdsfree(err);
            goto error;
        } else {
            serverLog(LL_NOTICE,
                "Master replied to PING, replication can continue...");
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_AUTH;
    }

    //如果需要认证，发送认证信息，等待认证结果
    //1，需要认证，
    //      状态转变:   REPL_STATE_SEND_AUTH     ->     REPL_STATE_RECEIVE_AUTH
    //      发送认证信息
    //2，不需要认证，
    //      状态转变:   REPL_STATE_SEND_AUTH     ->     REPL_STATE_SEND_PORT

    /* AUTH with the master if required. */
    if (server.repl_state == REPL_STATE_SEND_AUTH) {
        //是否需要认证
        if (server.masterauth) {
            err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"AUTH",server.masterauth,NULL);
            if (err) goto write_error;
            server.repl_state = REPL_STATE_RECEIVE_AUTH;
            return;
        } else {
            server.repl_state = REPL_STATE_SEND_PORT;
        }
    }

    //如果需要认证，这里接受认证返回消息
    //状态转变：REPL_STATE_RECEIVE_AUTH      —>      REPL_STATE_SEND_PORT

    /* Receive AUTH reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_AUTH) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        if (err[0] == '-') {
            serverLog(LL_WARNING,"Unable to AUTH to MASTER: %s",err);
            sdsfree(err);
            goto error;
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_PORT;
    }

    //发送slave的配置信息，即告诉master应该连接当前实例的那个端口
    //发送REPLCONF：port
    //状态转变：REPL_STATE_SEND_PORT     －>      REPL_STATE_RECEIVE_PORT

    /* Set the slave port, so that Master's INFO command can list the
     * slave listening port correctly. */
    if (server.repl_state == REPL_STATE_SEND_PORT) {
        sds port = sdsfromlonglong(server.port);
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "listening-port",port, NULL);
        sdsfree(port);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_PORT;
        return;
    }

    //上面发送完当前实例的配置，开始接受master的回复
    //状态转变：REPL_STATE_RECEIVE_PORT      －>      REPL_STATE_SEND_CAPA


    /* Receive REPLCONF listening-port reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_PORT) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                "REPLCONF listening-port: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_CAPA;
    }

    //告诉master当前实例的容量
    //发送REPLCONF：capa
    //状态转变：REPL_STATE_SEND_CAPA     ->      REPL_STATE_RECEIVE_CAPA

    /* Inform the master of our capabilities. While we currently send
     * just one capability, it is possible to chain new capabilities here
     * in the form of REPLCONF capa X capa Y capa Z ...
     * The master will ignore capabilities it does not understand. */
    if (server.repl_state == REPL_STATE_SEND_CAPA) {
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "capa","eof",NULL);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_CAPA;
        return;
    }

    //接受上面的回复
    //状态转变：REPL_STATE_RECEIVE_CAPA      ->      REPL_STATE_SEND_PSYNC

    /* Receive CAPA reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_CAPA) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF capa. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                  "REPLCONF capa: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_PSYNC;
    } 

    //尝试着增量同步，如果之前没有cached master，slaveTryPartialResynchronization方法会执行全量同步
    //这里获取master的run id和全局的offset，从而在下一次重新连接的时候可能执行锃亮同步

    //状态转变：REPL_STATE_SEND_PSYNC    ->      REPL_STATE_RECEIVE_PSYNC

    /* Try a partial resynchonization. If we don't have a cached master
     * slaveTryPartialResynchronization() will at least try to use PSYNC
     * to start a full resynchronization so that we get the master run id
     * and the global offset, to try a partial resync at the next
     * reconnection attempt. */
    if (server.repl_state == REPL_STATE_SEND_PSYNC) {
        if (slaveTryPartialResynchronization(fd,0) == PSYNC_WRITE_ERROR) {
            err = sdsnew("Write error sending the PSYNC command.");
            goto write_error;
        }
        server.repl_state = REPL_STATE_RECEIVE_PSYNC;
        return;
    }

    //如果代码执行到这里，必须是已经同步完啦，否则报错哟

    /* If reached this point, we should be in REPL_STATE_RECEIVE_PSYNC. */
    if (server.repl_state != REPL_STATE_RECEIVE_PSYNC) {
        serverLog(LL_WARNING,"syncWithMaster(): state machine error, "
                             "state should be RECEIVE_PSYNC but is %d",
                             server.repl_state);
        goto error;
    }

    psync_result = slaveTryPartialResynchronization(fd,1);
    if (psync_result == PSYNC_WAIT_REPLY) return; /* Try again later... */

    /* Note: if PSYNC does not return WAIT_REPLY, it will take care of
     * uninstalling the read handler from the file descriptor. */

    if (psync_result == PSYNC_CONTINUE) {
        serverLog(LL_NOTICE, "MASTER <-> SLAVE sync: Master accepted a Partial Resynchronization.");
        return;
    }

    /* PSYNC failed or is not supported: we want our slaves to resync with us
     * as well, if we have any (chained replication case). The mater may
     * transfer us an entirely different data set and we have no way to
     * incrementally feed our slaves after that. */
    disconnectSlaves(); /* Force our slaves to resync with us as well. */
    freeReplicationBacklog(); /* Don't allow our chained slaves to PSYNC. */

    /* Fall back to SYNC if needed. Otherwise psync_result == PSYNC_FULLRESYNC
     * and the server.repl_master_runid and repl_master_initial_offset are
     * already populated. */
    if (psync_result == PSYNC_NOT_SUPPORTED) {
        serverLog(LL_NOTICE,"Retrying with SYNC...");
        if (syncWrite(fd,"SYNC\r\n",6,server.repl_syncio_timeout*1000) == -1) {
            serverLog(LL_WARNING,"I/O error writing to MASTER: %s",
                strerror(errno));
            goto error;
        }
    }

    /* Prepare a suitable temp file for bulk transfer */
    while(maxtries--) {
        snprintf(tmpfile,256,
            "temp-%d.%ld.rdb",(int)server.unixtime,(long int)getpid());
        dfd = open(tmpfile,O_CREAT|O_WRONLY|O_EXCL,0644);
        if (dfd != -1) break;
        sleep(1);
    }
    if (dfd == -1) {
        serverLog(LL_WARNING,"Opening the temp file needed for MASTER <-> SLAVE synchronization: %s",strerror(errno));
        goto error;
    }

    /* Setup the non blocking download of the bulk file. */
    if (aeCreateFileEvent(server.el,fd, AE_READABLE,readSyncBulkPayload,NULL)
            == AE_ERR)
    {
        serverLog(LL_WARNING,
            "Can't create readable event for SYNC: %s (fd=%d)",
            strerror(errno),fd);
        goto error;
    }

    server.repl_state = REPL_STATE_TRANSFER;
    server.repl_transfer_size = -1;
    server.repl_transfer_read = 0;
    server.repl_transfer_last_fsync_off = 0;
    server.repl_transfer_fd = dfd;
    server.repl_transfer_lastio = server.unixtime;
    server.repl_transfer_tmpfile = zstrdup(tmpfile);
    return;

error:
    aeDeleteFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE);
    close(fd);
    server.repl_transfer_s = -1;
    server.repl_state = REPL_STATE_CONNECT;
    return;

write_error: /* Handle sendSynchronousCommand(SYNC_CMD_WRITE) errors. */
    serverLog(LL_WARNING,"Sending command to master in replication handshake: %s", err);
    sdsfree(err);
    goto error;
}

//建立和master的连接
//注册与master连接的读写I/O事件，事件处理器为syncWithMaster
//状态为REPL_STATE_CONNECTING

int connectWithMaster(void) {
    int fd;

    fd = anetTcpNonBlockBestEffortBindConnect(NULL,
        server.masterhost,server.masterport,NET_FIRST_BIND_ADDR);
    if (fd == -1) {
        serverLog(LL_WARNING,"Unable to connect to MASTER: %s",
            strerror(errno));
        return C_ERR;
    }

    if (aeCreateFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE,syncWithMaster,NULL) ==
            AE_ERR)
    {
        close(fd);
        serverLog(LL_WARNING,"Can't create readable event for SYNC");
        return C_ERR;
    }

    server.repl_transfer_lastio = server.unixtime;
    server.repl_transfer_s = fd;
    server.repl_state = REPL_STATE_CONNECTING;
    return C_OK;
}

//取消监听网络I／O的读写事件

/* This function can be called when a non blocking connection is currently
 * in progress to undo it.
 * Never call this function directly, use cancelReplicationHandshake() instead.
 */
void undoConnectWithMaster(void) {
    int fd = server.repl_transfer_s;

    aeDeleteFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE);
    close(fd);
    server.repl_transfer_s = -1;
}

//取消异步下载RDB文件

/* Abort the async download of the bulk dataset while SYNC-ing with master.
 * Never call this function directly, use cancelReplicationHandshake() instead.
 */
void replicationAbortSyncTransfer(void) {
    serverAssert(server.repl_state == REPL_STATE_TRANSFER);
    undoConnectWithMaster();
    close(server.repl_transfer_fd);
    unlink(server.repl_transfer_tmpfile);
    zfree(server.repl_transfer_tmpfile);
}

//当前函数用于取消非阻塞的复制
//1，如果复制状态是REPL_STATE_TRANSFER，则说明正在传输RDB文件，取消传输
//2，如果复制状态是REPL_STATE_CONNECTING或者正在连接，则断开和master的连接

//将复制状态设置为REPL_STATE_CONNECT

/* This function aborts a non blocking replication attempt if there is one
 * in progress, by canceling the non-blocking connect attempt or
 * the initial bulk transfer.
 *
 * If there was a replication handshake in progress 1 is returned and
 * the replication state (server.repl_state) set to REPL_STATE_CONNECT.
 *
 * Otherwise zero is returned and no operation is perforemd at all. */
int cancelReplicationHandshake(void) {
    if (server.repl_state == REPL_STATE_TRANSFER) {
        replicationAbortSyncTransfer();//取消传输RDB文件
        server.repl_state = REPL_STATE_CONNECT;
    } else if (server.repl_state == REPL_STATE_CONNECTING ||
               slaveIsInHandshakeState())
    {
        undoConnectWithMaster();
        server.repl_state = REPL_STATE_CONNECT;
    } else {
        return 0;
    }
    return 1;
}

//设置指定的host和port为当前的master

/* Set replication to the specified master address and port. */
void replicationSetMaster(char *ip, int port) {
    sdsfree(server.masterhost);
    server.masterhost = sdsnew(ip);
    server.masterport = port;
    if (server.master) freeClient(server.master);
    disconnectAllBlockedClients(); /* Clients blocked in master, now slave. */ //断开阻塞的连接
    disconnectSlaves(); /* Force our slaves to resync with us as well. */
    replicationDiscardCachedMaster(); /* Don't try a PSYNC. */
    freeReplicationBacklog(); /* Don't allow our chained slaves to PSYNC. */ //释放backlog
    cancelReplicationHandshake();
    server.repl_state = REPL_STATE_CONNECT;
    server.master_repl_offset = 0;
    server.repl_down_since = 0;
}

//把当前实例的master信息清除

/* Cancel replication, setting the instance as a master itself. */
void replicationUnsetMaster(void) {
    if (server.masterhost == NULL) return; /* Nothing to do. */
    sdsfree(server.masterhost);
    server.masterhost = NULL;
    if (server.master) {
        if (listLength(server.slaves) == 0) {
            //如果当前实例即将成为master，且没有slaves，则从master继承offset，在一定条件下
            //这可以使得不同复制实例可以比较他们之间的复制进度。

            /* If this instance is turned into a master and there are no
             * slaves, it inherits the replication offset from the master.
             * Under certain conditions this makes replicas comparable by
             * replication offset to understand what is the most updated. */
            server.master_repl_offset = server.master->reploff;
            //释放堆积缓冲区
            freeReplicationBacklog();
        }
        //释放保存master的内存空间
        freeClient(server.master);
    }
    replicationDiscardCachedMaster();
    cancelReplicationHandshake();
    server.repl_state = REPL_STATE_NONE;
}

//这个方法在slave失去和master的连接之后被调用。

/* This function is called when the slave lose the connection with the
 * master into an unexpected way. */
void replicationHandleMasterDisconnection(void) {
    server.master = NULL;
    server.repl_state = REPL_STATE_CONNECT;
    server.repl_down_since = server.unixtime;

    //我们失去了和master的连接，我们还没断开和slave的连接，因为之后我们可能会和master进行PSYNC。
    //当需要全量同步的时候才会断开和slaves的连接。

    /* We lost connection with our master, don't disconnect slaves yet,
     * maybe we'll be able to PSYNC with our master later. We'll disconnect
     * the slaves only if we'll have to do a full resync with our master. */
}

void slaveofCommand(client *c) {
    /* SLAVEOF is not allowed in cluster mode as replication is automatically
     * configured using the current address of the master node. */
    if (server.cluster_enabled) {
        addReplyError(c,"SLAVEOF not allowed in cluster mode.");
        return;
    }

    //如: ./redis-server --slaveof 127.0.0.1 6379
    //如果命令为:./redis-server --slaveof NO ONE，则把当前实例设置为master，否则说明master不是当前实例
    //argv[1] == host
    //argc[2] == port

    /* The special host/port combination "NO" "ONE" turns the instance
     * into a master. Otherwise the new master address is set. */
    if (!strcasecmp(c->argv[1]->ptr,"no") &&
        !strcasecmp(c->argv[2]->ptr,"one")) {
        if (server.masterhost) {
            replicationUnsetMaster();//清除当前的master信息并缓存起来
            sds client = catClientInfoString(sdsempty(),c);
            serverLog(LL_NOTICE,"MASTER MODE enabled (user request from '%s')",
                client);
            sdsfree(client);
        }
    } else {//设置了host和port，当前实例不是master
        long port;

        //将字符串port转换为longlong的类型
        if ((getLongFromObjectOrReply(c, c->argv[2], &port, NULL) != C_OK))
            return;

        //如果想要附属的master之前已经附属过了，则直接返回
        /* Check if we are already attached to the specified slave */
        if (server.masterhost && !strcasecmp(server.masterhost,c->argv[1]->ptr)
            && server.masterport == port) {
            serverLog(LL_NOTICE,"SLAVE OF would result into synchronization with the master we are already connected with. No operation performed.");
            addReplySds(c,sdsnew("+OK Already connected to specified master\r\n"));
            return;
        }
        //如果之前没有附属过master或者第一次连接指定的master则继续
        /* There was no previous master or the user specified a different one,
         * we can continue. */
        replicationSetMaster(c->argv[1]->ptr, port);
        sds client = catClientInfoString(sdsempty(),c);
        serverLog(LL_NOTICE,"SLAVE OF %s:%d enabled (user request from '%s')",
            server.masterhost, server.masterport, client);
        sdsfree(client);
    }
    addReply(c,shared.ok);
}

/* ROLE command: provide information about the role of the instance
 * (master or slave) and additional information related to replication
 * in an easy to process format. */
void roleCommand(client *c) {
    if (server.masterhost == NULL) {
        listIter li;
        listNode *ln;
        void *mbcount;
        int slaves = 0;

        addReplyMultiBulkLen(c,3);
        addReplyBulkCBuffer(c,"master",6);
        addReplyLongLong(c,server.master_repl_offset);
        mbcount = addDeferredMultiBulkLength(c);
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            char ip[NET_IP_STR_LEN];

            if (anetPeerToString(slave->fd,ip,sizeof(ip),NULL) == -1) continue;
            if (slave->replstate != SLAVE_STATE_ONLINE) continue;
            addReplyMultiBulkLen(c,3);
            addReplyBulkCString(c,ip);
            addReplyBulkLongLong(c,slave->slave_listening_port);
            addReplyBulkLongLong(c,slave->repl_ack_off);
            slaves++;
        }
        setDeferredMultiBulkLength(c,mbcount,slaves);
    } else {
        char *slavestate = NULL;

        addReplyMultiBulkLen(c,5);
        addReplyBulkCBuffer(c,"slave",5);
        addReplyBulkCString(c,server.masterhost);
        addReplyLongLong(c,server.masterport);
        if (slaveIsInHandshakeState()) {
            slavestate = "handshake";
        } else {
            switch(server.repl_state) {
            case REPL_STATE_NONE: slavestate = "none"; break;
            case REPL_STATE_CONNECT: slavestate = "connect"; break;
            case REPL_STATE_CONNECTING: slavestate = "connecting"; break;
            case REPL_STATE_TRANSFER: slavestate = "sync"; break;
            case REPL_STATE_CONNECTED: slavestate = "connected"; break;
            default: slavestate = "unknown"; break;
            }
        }
        addReplyBulkCString(c,slavestate);
        addReplyLongLong(c,server.master ? server.master->reploff : -1);
    }
}

//向master发送REPLCONF AVCK命令，让master知道当前slave的复制进度

/* Send a REPLCONF ACK command to the master to inform it about the current
 * processed offset. If we are not connected with a master, the command has
 * no effects. */
void replicationSendAck(void) {
    client *c = server.master;

    if (c != NULL) {
        c->flags |= CLIENT_MASTER_FORCE_REPLY;
        addReplyMultiBulkLen(c,3);
        addReplyBulkCString(c,"REPLCONF");
        addReplyBulkCString(c,"ACK");
        addReplyBulkLongLong(c,c->reploff);
        c->flags &= ~CLIENT_MASTER_FORCE_REPLY;
    }
}

/* ---------------------- MASTER CACHING FOR PSYNC -------------------------- */

//为了实现增量同步、我们需要记住slave与master断开之前的master信息，这个信息缓存在server.cached_master中。
//下面方法总是刷新cached_master的值。

//这个方法被freeClient调用，为了缓存master的客户端信息，freeClient将会在这个方法返回之后尽可能快的返回

//其他处理cached_master的方法有：
//replicationResurrectCachedMaster方法会kill掉client，原因是client不再不需要了。
//replicationResurrectCachedMaster用于PSYNC成功的握手之后重新激活cached master。

/* In order to implement partial synchronization we need to be able to cache
 * our master's client structure after a transient disconnection.
 * It is cached into server.cached_master and flushed away using the following
 * functions. */

/* This function is called by freeClient() in order to cache the master
 * client structure instead of destryoing it. freeClient() will return
 * ASAP after this function returns, so every action needed to avoid problems
 * with a client that is really "suspended" has to be done by this function.
 *
 * The other functions that will deal with the cached master are:
 *
 * replicationDiscardCachedMaster() that will make sure to kill the client
 * as for some reason we don't want to use it in the future.
 *
 * replicationResurrectCachedMaster() that is used after a successful PSYNC
 * handshake in order to reactivate the cached master.
 */
void replicationCacheMaster(client *c) {
    serverAssert(server.master != NULL && server.cached_master == NULL);
    serverLog(LL_NOTICE,"Caching the disconnected master state.");

    /* Unlink the client from the server structures. */
    unlinkClient(c);

    //保存master，之后server.master将会被通过replicationHandleMasterDisconnection设置为null。
    //这应该是slave断开master之后。

    /* Save the master. Server.master will be set to null later by
     * replicationHandleMasterDisconnection(). */
    server.cached_master = server.master;

    /* Invalidate the Peer ID cache. */
    if (c->peerid) {
        sdsfree(c->peerid);
        c->peerid = NULL;
    }

    //freeClient实际上是将server.masrer备份并清空。

    /* Caching the master happens instead of the actual freeClient() call,
     * so make sure to adjust the replication state. This function will
     * also set server.master to NULL. */
    replicationHandleMasterDisconnection();
}

//清空cached_master

/* Free a cached master, called when there are no longer the conditions for
 * a partial resync on reconnection. */
void replicationDiscardCachedMaster(void) {
    if (server.cached_master == NULL) return;

    serverLog(LL_NOTICE,"Discarding previously cached master state.");
    server.cached_master->flags &= ~CLIENT_MASTER;
    freeClient(server.cached_master);
    server.cached_master = NULL;
}

//修改缓存的master为当前的master
//状态转变：   ->  REPL_STATE_CONNECTED

/* Turn the cached master into the current master, using the file descriptor
 * passed as argument as the socket for the new master.
 *
 * This function is called when successfully setup a partial resynchronization
 * so the stream of data that we'll receive will start from were this
 * master left. */
void replicationResurrectCachedMaster(int newfd) {
    server.master = server.cached_master;
    server.cached_master = NULL;
    server.master->fd = newfd;
    server.master->flags &= ~(CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP);
    server.master->authenticated = 1;
    server.master->lastinteraction = server.unixtime;
    server.repl_state = REPL_STATE_CONNECTED;

    /* Re-add to the list of clients. */
    listAddNodeTail(server.clients,server.master);
    if (aeCreateFileEvent(server.el, newfd, AE_READABLE,
                          readQueryFromClient, server.master)) {
        serverLog(LL_WARNING,"Error resurrecting the cached master, impossible to add the readable handler: %s", strerror(errno));
        freeClientAsync(server.master); /* Close ASAP. */
    }

    //如果客户端有挂起的操作，这个时候需要处理这些

    /* We may also need to install the write handler as well if there is
     * pending data in the write buffers. */
    if (clientHasPendingReplies(server.master)) {
        if (aeCreateFileEvent(server.el, newfd, AE_WRITABLE,
                          sendReplyToClient, server.master)) {
            serverLog(LL_WARNING,"Error resurrecting the cached master, impossible to add the writable handler: %s", strerror(errno));
            freeClientAsync(server.master); /* Close ASAP. */
        }
    }
}

/* ------------------------- MIN-SLAVES-TO-WRITE  --------------------------- */

/* This function counts the number of slaves with lag <= min-slaves-max-lag.
 * If the option is active, the server will prevent writes if there are not
 * enough connected slaves with the specified lag (or less). */
void refreshGoodSlavesCount(void) {
    listIter li;
    listNode *ln;
    int good = 0;

    if (!server.repl_min_slaves_to_write ||
        !server.repl_min_slaves_max_lag) return;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;
        time_t lag = server.unixtime - slave->repl_ack_time;

        if (slave->replstate == SLAVE_STATE_ONLINE &&
            lag <= server.repl_min_slaves_max_lag) good++;
    }
    server.repl_good_slaves_count = good;
}

/* ----------------------- REPLICATION SCRIPT CACHE --------------------------
 * The goal of this code is to keep track of scripts already sent to every
 * connected slave, in order to be able to replicate EVALSHA as it is without
 * translating it to EVAL every time it is possible.
 *
 * We use a capped collection implemented by a hash table for fast lookup
 * of scripts we can send as EVALSHA, plus a linked list that is used for
 * eviction of the oldest entry when the max number of items is reached.
 *
 * We don't care about taking a different cache for every different slave
 * since to fill the cache again is not very costly, the goal of this code
 * is to avoid that the same big script is trasmitted a big number of times
 * per second wasting bandwidth and processor speed, but it is not a problem
 * if we need to rebuild the cache from scratch from time to time, every used
 * script will need to be transmitted a single time to reappear in the cache.
 *
 * This is how the system works:
 *
 * 1) Every time a new slave connects, we flush the whole script cache.
 * 2) We only send as EVALSHA what was sent to the master as EVALSHA, without
 *    trying to convert EVAL into EVALSHA specifically for slaves.
 * 3) Every time we trasmit a script as EVAL to the slaves, we also add the
 *    corresponding SHA1 of the script into the cache as we are sure every
 *    slave knows about the script starting from now.
 * 4) On SCRIPT FLUSH command, we replicate the command to all the slaves
 *    and at the same time flush the script cache.
 * 5) When the last slave disconnects, flush the cache.
 * 6) We handle SCRIPT LOAD as well since that's how scripts are loaded
 *    in the master sometimes.
 */

/* Initialize the script cache, only called at startup. */
void replicationScriptCacheInit(void) {
    server.repl_scriptcache_size = 10000;
    server.repl_scriptcache_dict = dictCreate(&replScriptCacheDictType,NULL);
    server.repl_scriptcache_fifo = listCreate();
}

/* Empty the script cache. Should be called every time we are no longer sure
 * that every slave knows about all the scripts in our set, or when the
 * current AOF "context" is no longer aware of the script. In general we
 * should flush the cache:
 *
 * 1) Every time a new slave reconnects to this master and performs a
 *    full SYNC (PSYNC does not require flushing).
 * 2) Every time an AOF rewrite is performed.
 * 3) Every time we are left without slaves at all, and AOF is off, in order
 *    to reclaim otherwise unused memory.
 */
void replicationScriptCacheFlush(void) {
    dictEmpty(server.repl_scriptcache_dict,NULL);
    listRelease(server.repl_scriptcache_fifo);
    server.repl_scriptcache_fifo = listCreate();
}

/* Add an entry into the script cache, if we reach max number of entries the
 * oldest is removed from the list. */
void replicationScriptCacheAdd(sds sha1) {
    int retval;
    sds key = sdsdup(sha1);

    /* Evict oldest. */
    if (listLength(server.repl_scriptcache_fifo) == server.repl_scriptcache_size)
    {
        listNode *ln = listLast(server.repl_scriptcache_fifo);
        sds oldest = listNodeValue(ln);

        retval = dictDelete(server.repl_scriptcache_dict,oldest);
        serverAssert(retval == DICT_OK);
        listDelNode(server.repl_scriptcache_fifo,ln);
    }

    /* Add current. */
    retval = dictAdd(server.repl_scriptcache_dict,key,NULL);
    listAddNodeHead(server.repl_scriptcache_fifo,key);
    serverAssert(retval == DICT_OK);
}

/* Returns non-zero if the specified entry exists inside the cache, that is,
 * if all the slaves are aware of this script SHA1. */
int replicationScriptCacheExists(sds sha1) {
    return dictFind(server.repl_scriptcache_dict,sha1) != NULL;
}

/* ----------------------- SYNCHRONOUS REPLICATION --------------------------
 * Redis synchronous replication design can be summarized in points:
 *
 * - Redis masters have a global replication offset, used by PSYNC.
 * - Master increment the offset every time new commands are sent to slaves.
 * - Slaves ping back masters with the offset processed so far.
 *
 * So synchronous replication adds a new WAIT command in the form:
 *
 *   WAIT <num_replicas> <milliseconds_timeout>
 *
 * That returns the number of replicas that processed the query when
 * we finally have at least num_replicas, or when the timeout was
 * reached.
 *
 * The command is implemented in this way:
 *
 * - Every time a client processes a command, we remember the replication
 *   offset after sending that command to the slaves.
 * - When WAIT is called, we ask slaves to send an acknowledgement ASAP.
 *   The client is blocked at the same time (see blocked.c).
 * - Once we receive enough ACKs for a given offset or when the timeout
 *   is reached, the WAIT command is unblocked and the reply sent to the
 *   client.
 */

/* This just set a flag so that we broadcast a REPLCONF GETACK command
 * to all the slaves in the beforeSleep() function. Note that this way
 * we "group" all the clients that want to wait for synchronouns replication
 * in a given event loop iteration, and send a single GETACK for them all. */
void replicationRequestAckFromSlaves(void) {
    server.get_ack_from_slaves = 1;
}

/* Return the number of slaves that already acknowledged the specified
 * replication offset. */
int replicationCountAcksByOffset(long long offset) {
    listIter li;
    listNode *ln;
    int count = 0;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (slave->replstate != SLAVE_STATE_ONLINE) continue;
        if (slave->repl_ack_off >= offset) count++;
    }
    return count;
}

/* WAIT for N replicas to acknowledge the processing of our latest
 * write command (and all the previous commands). */
void waitCommand(client *c) {
    mstime_t timeout;
    long numreplicas, ackreplicas;
    long long offset = c->woff;

    /* Argument parsing. */
    if (getLongFromObjectOrReply(c,c->argv[1],&numreplicas,NULL) != C_OK)
        return;
    if (getTimeoutFromObjectOrReply(c,c->argv[2],&timeout,UNIT_MILLISECONDS)
        != C_OK) return;

    /* First try without blocking at all. */
    ackreplicas = replicationCountAcksByOffset(c->woff);
    if (ackreplicas >= numreplicas || c->flags & CLIENT_MULTI) {
        addReplyLongLong(c,ackreplicas);
        return;
    }

    /* Otherwise block the client and put it into our list of clients
     * waiting for ack from slaves. */
    c->bpop.timeout = timeout;
    c->bpop.reploffset = offset;
    c->bpop.numreplicas = numreplicas;
    listAddNodeTail(server.clients_waiting_acks,c);
    blockClient(c,BLOCKED_WAIT);

    /* Make sure that the server will send an ACK request to all the slaves
     * before returning to the event loop. */
    replicationRequestAckFromSlaves();
}

/* This is called by unblockClient() to perform the blocking op type
 * specific cleanup. We just remove the client from the list of clients
 * waiting for replica acks. Never call it directly, call unblockClient()
 * instead. */
void unblockClientWaitingReplicas(client *c) {
    listNode *ln = listSearchKey(server.clients_waiting_acks,c);
    serverAssert(ln != NULL);
    listDelNode(server.clients_waiting_acks,ln);
}

/* Check if there are clients blocked in WAIT that can be unblocked since
 * we received enough ACKs from slaves. */
void processClientsWaitingReplicas(void) {
    long long last_offset = 0;
    int last_numreplicas = 0;

    listIter li;
    listNode *ln;

    listRewind(server.clients_waiting_acks,&li);
    while((ln = listNext(&li))) {
        client *c = ln->value;

        /* Every time we find a client that is satisfied for a given
         * offset and number of replicas, we remember it so the next client
         * may be unblocked without calling replicationCountAcksByOffset()
         * if the requested offset / replicas were equal or less. */
        if (last_offset && last_offset > c->bpop.reploffset &&
                           last_numreplicas > c->bpop.numreplicas)
        {
            unblockClient(c);
            addReplyLongLong(c,last_numreplicas);
        } else {
            int numreplicas = replicationCountAcksByOffset(c->bpop.reploffset);

            if (numreplicas >= c->bpop.numreplicas) {
                last_offset = c->bpop.reploffset;
                last_numreplicas = numreplicas;
                unblockClient(c);
                addReplyLongLong(c,numreplicas);
            }
        }
    }
}

/* Return the slave replication offset for this instance, that is
 * the offset for which we already processed the master replication stream. */
long long replicationGetSlaveOffset(void) {
    long long offset = 0;

    if (server.masterhost != NULL) {
        if (server.master) {
            offset = server.master->reploff;
        } else if (server.cached_master) {
            offset = server.cached_master->reploff;
        }
    }
    /* offset may be -1 when the master does not support it at all, however
     * this function is designed to return an offset that can express the
     * amount of data processed by the master, so we return a positive
     * integer. */
    if (offset < 0) offset = 0;
    return offset;
}

/* --------------------------- REPLICATION CRON  ---------------------------- */

//复制定时任务

/* Replication cron function, called 1 time per second. */
void replicationCron(void) {
    static long long replication_cron_loops = 0;

    //针对slave
    //1，指定了master
    //2，复制状态是（正在连接或者正在握手）
    //3，距离上次复制的时间大于复制超时时间

    //满足上面三个条件，则取消握手


    /* Non blocking connection timeout? */
    if (server.masterhost &&
        (server.repl_state == REPL_STATE_CONNECTING ||
         slaveIsInHandshakeState()) &&
         (time(NULL)-server.repl_transfer_lastio) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"Timeout connecting to the MASTER...");
        cancelReplicationHandshake();
    }

    //针对slave
    //如果指定了master，且正在传输RDB文件，且距离上一次传输的时间大于复制超时时间

    //则取消握手

    /* Bulk transfer I/O timeout? */
    if (server.masterhost && server.repl_state == REPL_STATE_TRANSFER &&
        (time(NULL)-server.repl_transfer_lastio) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"Timeout receiving bulk data from MASTER... If the problem persists try to set the 'repl-timeout' parameter in redis.conf to a larger value.");
        cancelReplicationHandshake();
    }

    //针对slave
    //指定了master，复制状态为已经连接了且距离上一次的交互时间大于复制超时时间

    //释放master

    /* Timed out master when we are an already connected slave? */
    if (server.masterhost && server.repl_state == REPL_STATE_CONNECTED &&
        (time(NULL)-server.master->lastinteraction) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"MASTER timeout: no data nor PING received...");
        freeClient(server.master);
    }

    //针对slave
    //检查是否需要和master建立连接
    //包括状态迁移

    /* Check if we should connect to a MASTER */
    if (server.repl_state == REPL_STATE_CONNECT) {
        serverLog(LL_NOTICE,"Connecting to MASTER %s:%d",
            server.masterhost, server.masterport);
        if (connectWithMaster() == C_OK) {
            serverLog(LL_NOTICE,"MASTER <-> SLAVE sync started");
        }
    }

    //针对slave
    //向master发送ACK
    //我们不向不支持PSYNC以及replication offset的master发送ACK

    /* Send ACK to master from time to time.
     * Note that we do not send periodic acks to masters that don't
     * support PSYNC and replication offsets. */
    if (server.masterhost && server.master &&
        !(server.master->flags & CLIENT_PRE_PSYNC))
        replicationSendAck();

    //针对master
    //如果当前有slaves，则ping他们
    //因此slaves可以实现显式的master超时管理
    //而且可以检测网络连接是不是挂了

    /* If we have attached slaves, PING them from time to time.
     * So slaves can implement an explicit timeout to masters, and will
     * be able to detect a link disconnection even if the TCP connection
     * will not actually go down. */
    listIter li;
    listNode *ln;
    robj *ping_argv[1];

    //针对master
    //首先、pingslaves的时间间隔为一定的频率

    /* First, send PING according to ping_slave_period. */
    if ((replication_cron_loops % server.repl_ping_slave_period) == 0) {
        ping_argv[0] = createStringObject("PING",4);
        replicationFeedSlaves(server.slaves, server.slaveseldb,
            ping_argv, 1);
        decrRefCount(ping_argv[0]);
    }

    //针对master
    //其次、在同步之前发送一个换行符给slaves，意思是slaves需要等待master创建RDB文件
    //slaves接收到这个换行符将会刷新last－io时间，从而阻止timeout。在这个例子中我们
    //忽略ping的周期、每秒刷新一次连接，因为timeout是多个秒级别

    /* Second, send a newline to all the slaves in pre-synchronization
     * stage, that is, slaves waiting for the master to create the RDB file.
     * The newline will be ignored by the slave but will refresh the
     * last-io timer preventing a timeout. In this case we ignore the
     * ping period and refresh the connection once per second since certain
     * timeouts are set at a few seconds (example: PSYNC response). */
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        //如果slave正处于等待master开始备份RDB文件的状态
        //或者slave正处于等待master结束备份RDB文件的状态且复制类型不为diskless类型

        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START ||
            (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END &&
             server.rdb_child_type != RDB_CHILD_TYPE_SOCKET))
        {
            if (write(slave->fd, "\n", 1) == -1) {
                /* Don't worry, it's just a ping. */
            }
        }
    }

    //针对master
    //释放连接超时的slave

    /* Disconnect timedout slaves. */
    if (listLength(server.slaves)) {
        listIter li;
        listNode *ln;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate != SLAVE_STATE_ONLINE) continue;
            if (slave->flags & CLIENT_PRE_PSYNC) continue;
            if ((server.unixtime - slave->repl_ack_time) > server.repl_timeout)
            {
                serverLog(LL_WARNING, "Disconnecting timedout slave: %s",
                    replicationGetSlaveName(slave));
                freeClient(slave);
            }
        }
    }

    //如果当前实例没有slaves，并且有backlog占用内存，且超过了这块内存的存活时间，则释放

    /* If we have no attached slaves and there is a replication backlog
     * using memory, free it after some (configured) time. */
    if (listLength(server.slaves) == 0 && server.repl_backlog_time_limit &&
        server.repl_backlog)
    {
        time_t idle = server.unixtime - server.repl_no_slaves_since;

        if (idle > server.repl_backlog_time_limit) {
            freeReplicationBacklog();
            serverLog(LL_NOTICE,
                "Replication backlog freed after %d seconds "
                "without connected slaves.",
                (int) server.repl_backlog_time_limit);
        }
    }

    //如果AO被关闭，且没有slaves了，我们可以清空复制脚本

    /* If AOF is disabled and we no longer have attached slaves, we can
     * free our Replication Script Cache as there is no need to propagate
     * EVALSHA at all. */
    if (listLength(server.slaves) == 0 &&
        server.aof_state == AOF_OFF &&
        listLength(server.repl_scriptcache_fifo) != 0)
    {
        replicationScriptCacheFlush();
    }

    //如果是Diskless复制模式，且有slave正在处于等待发送RDB文件的状态，如果到了备份RDB文件的时候
    //这段代码也适用于当diskless被关闭的时候，触发备份RDB文件

    /* If we are using diskless replication and there are slaves waiting
     * in WAIT_BGSAVE_START state, check if enough seconds elapsed and
     * start a BGSAVE.
     *
     * This code is also useful to trigger a BGSAVE if the diskless
     * replication was turned off with CONFIG SET, while there were already
     * slaves in WAIT_BGSAVE_START state. */
    if (server.rdb_child_pid == -1 && server.aof_child_pid == -1) {
        time_t idle, max_idle = 0;
        int slaves_waiting = 0;
        int mincapa = -1;
        listNode *ln;
        listIter li;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                idle = server.unixtime - slave->lastinteraction;
                if (idle > max_idle) max_idle = idle;
                slaves_waiting++;
                mincapa = (mincapa == -1) ? slave->slave_capa :
                                            (mincapa & slave->slave_capa);
            }
        }

        //如果有slave正在WAIT_BGSAVE_START状态，且可以备份RDB文件了
        if (slaves_waiting && max_idle > server.repl_diskless_sync_delay) {
            //开启备份RDB文件的子进程，通常用于diskless状态，活着配置文件被变更而处于disk target状态
            /* Start a BGSAVE. Usually with socket target, or with disk target
             * if there was a recent socket -> disk config change. */
            startBgsaveForReplication(mincapa);
        }
    }

    /* Refresh the number of slaves with lag <= min-slaves-max-lag. */
    refreshGoodSlavesCount();
    replication_cron_loops++; /* Incremented with frequency 1 HZ. */
}
