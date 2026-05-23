import "./welcome.css";

import React from 'react';
import PropTypes from 'prop-types';
import { Link } from "react-router-dom";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';

import VeloReportViewer from "../artifacts/reporting.jsx";
import T from '../i8n/i8n.jsx';
import UserConfig from '../core/user.jsx';

/*
  Landing page shown at "/" and "/welcome".

  Server admins can customize the embedded report
  (Custom.Server.Internal.Welcome) so we still render it below the
  action cards — admins do not lose any customization.
*/

const QUICK_ACTIONS = [
    {
        to: "/search/all",
        icon: "search",
        title: "Search Clients",
        desc: "Find a host by name, label, IP or client id.",
        kbd: "/",
    },
    {
        to: "/dashboard",
        icon: "chart-line",
        title: "Server Dashboard",
        desc: "Live health and activity for the Velociraptor server.",
    },
    {
        to: "/hunts",
        icon: "crosshairs",
        title: "Hunt Manager",
        desc: "Run an artifact across many hosts at once.",
    },
    {
        to: "/artifacts",
        icon: "wrench",
        title: "View Artifacts",
        desc: "Browse, edit and test the artifact library.",
    },
    {
        to: "/collected/server",
        icon: "server",
        title: "Server Artifacts",
        desc: "Inspect artifacts that have run on the server.",
    },
    {
        to: "/notebooks",
        icon: "book",
        title: "Notebooks",
        desc: "Analyse results, write VQL and share findings.",
    },
];

const ADMIN_ACTIONS = [
    {
        to: "/users",
        icon: "user",
        title: "Users",
        desc: "Manage user accounts, roles and org assignments.",
    },
    {
        to: "/secrets",
        icon: "key",
        title: "Secrets",
        desc: "Store credentials artifacts can reference securely.",
    },
];

class ActionCard extends React.Component {
    static propTypes = {
        to: PropTypes.string.isRequired,
        icon: PropTypes.string.isRequired,
        title: PropTypes.string.isRequired,
        desc: PropTypes.string.isRequired,
        kbd: PropTypes.string,
    }

    render() {
        let {to, icon, title, desc, kbd} = this.props;
        return (
            <Link to={to} className="welcome-action-card">
              <span className="action-icon">
                <FontAwesomeIcon icon={icon} />
              </span>
              <p className="action-title">{T(title)}</p>
              <p className="action-desc">{T(desc)}</p>
              {kbd && (
                  <div className="action-kbd">
                    {T("Shortcut")}: <kbd>{kbd}</kbd>
                  </div>
              )}
            </Link>
        );
    }
}

export default class Welcome extends React.Component {
    static contextType = UserConfig;

    render() {
        let username = (this.context && this.context.traits &&
                        this.context.traits.username) || "";
        let is_admin = this.context && this.context.traits &&
              this.context.traits.Permissions && (
                  this.context.traits.Permissions.org_admin ||
                  this.context.traits.Permissions.server_admin);

        let greeting = username
              ? T("Welcome back") + ", " + username
              : T("Welcome to Velociraptor");

        return (
            <div className="welcome-page">
              <div className="welcome-hero">
                <h1>{greeting}</h1>
                <p>{T("Pick a place to start. Everything here is also reachable from the sidebar on the left.")}</p>
              </div>

              <div className="welcome-section-title">{T("Quick Actions")}</div>
              <div className="welcome-actions">
                {QUICK_ACTIONS.map((a, i) => (
                    <ActionCard key={i} {...a} />
                ))}
              </div>

              {is_admin && (
                  <>
                    <div className="welcome-section-title">{T("Administration")}</div>
                    <div className="welcome-actions">
                      {ADMIN_ACTIONS.map((a, i) => (
                          <ActionCard key={i} {...a} />
                      ))}
                    </div>
                  </>
              )}

              <div className="welcome-tips">
                <strong>{T("Tips")}</strong>
                <ul>
                  <li>{T("Press ? at any time to see all keyboard shortcuts.")}</li>
                  <li>{T("Click the host name in the top bar to jump back to the selected client.")}</li>
                  <li>{T("Most tables support filtering — look for the funnel icon in the toolbar.")}</li>
                </ul>
              </div>

              <div className="welcome-server-report">
                <VeloReportViewer
                  type="CLIENT"
                  artifact="Custom.Server.Internal.Welcome" />
              </div>
            </div>
        );
    }
}
