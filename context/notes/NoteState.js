import NoteContext from "./noteContext";
import { useState } from "react";

const NoteState = (props) => {
    const host = "http://localhost:5000"
    const notesInitial = []
    const [notes, setNotes] = useState(notesInitial)

    //   Get all Notes
    const getNotes = async () => {
        // API Call
        const response = await fetch(`${host}/api/notes/fetchallnotes`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "auth-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjU4Y2VmMWI4ODJjY2U0YjA3MDk4MWQzIn0sImlhdCI6MTcwMzczNTA2N30.auaBWZZLRxdVYhE24A-zJG8UJyHw_AVJWezYFHQtcuM"
            }
        });
        const json = await response.json();
        setNotes(json);

    }

// Add a Note
const addNote = async (title, description, tag) => {
    try {
        // API Call
        const response = await fetch(`${host}/api/notes/addnote`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "auth-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjU4Y2VmMWI4ODJjY2U0YjA3MDk4MWQzIn0sImlhdCI6MTcwMzczNTA2N30.auaBWZZLRxdVYhE24A-zJG8UJyHw_AVJWezYFHQtcuM"
            },
            body: JSON.stringify({ title, description, tag }),
        });

        if (!response.ok) {
            throw new Error('Failed to add note');
        }

        const note = await response.json();
        setNotes(notes.concat(note));
    } catch (error) {
        console.error('Error adding note:', error);
    }
}


    //   Delete a Note
    const deleteNote = async (id) => {
        // API CALL
        const response = await fetch(`${host}/api/notes/deletenote/${id}`, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
                "auth-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjU4Y2VmMWI4ODJjY2U0YjA3MDk4MWQzIn0sImlhdCI6MTcwMzczNTA2N30.auaBWZZLRxdVYhE24A-zJG8UJyHw_AVJWezYFHQtcuM"
            }
        });
        const json = await response.json();
        const newNotes = notes.filter((note) => { return note._id !== id })
        setNotes(newNotes);
    }

    //   Edit a Note
    const editNote = async (id, title, description, tag) => {
        // API Call
        const response = await fetch(`${host}/api/notes/updatenote/${id}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "auth-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjU4Y2VmMWI4ODJjY2U0YjA3MDk4MWQzIn0sImlhdCI6MTcwMzczNTA2N30.auaBWZZLRxdVYhE24A-zJG8UJyHw_AVJWezYFHQtcuM"
            },
            body: JSON.stringify({ title, description, tag }),
        });
        const json = await response.json();

        let newNotes = JSON.parse(JSON.stringify(notes))
        // /Logic to edit in client
        for (let index = 0; index < newNotes.length; index++) {
            const element = newNotes[index];
            if (element._id === id) {
                newNotes[index].title = title;
                newNotes[index].description = description;
                newNotes[index].tag = tag;
             break;
            }
        }
        setNotes(newNotes); 
    }


    return (
        <NoteContext.Provider value={{ notes, addNote, deleteNote, editNote, getNotes }}>
            {props.children}
        </NoteContext.Provider>
    )
}

export default NoteState;