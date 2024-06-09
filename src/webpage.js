function addsong(pathToImage, songTitle, artistName) {
    // create song element
    const song = document.createElement("div");
    song.className = "music-card"
    song.innerHTML += 
        `<img src="${pathToImage}.jpg" alt="Album Art" class="album-art">
        <div class="song-info">
            <div class="song-name">
                ${songTitle}
            </div>
            <div class="artist-name">
                ${artistName}
            </div>
        </div>`;
    // add song element
    document.getElementById("queue").appendChild(song);
}

document.getElementById("addSong").
            addEventListener("click", function(){addsong("path-to-img.jpg", "song title", "artist")});